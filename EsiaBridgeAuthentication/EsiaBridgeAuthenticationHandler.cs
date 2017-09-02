using Microsoft.Owin.Security.Infrastructure;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using Microsoft.Owin.Security;
using System.Threading.Tasks;
using Microsoft.Owin;
using System.Net;
using System.Text;
using System.Net.Http;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Infrastructure;
using EsiaBridgeAuthentication.Provider;
using System.Security.Claims;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace EsiaBridgeAuthentication
{
    public class EsiaBridgeAuthenticationHandler : AuthenticationHandler<EsiaBridgeAuthenticationOptions>
    {
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";

        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public EsiaBridgeAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            _httpClient = httpClient;
            _logger = logger;
        }

        //step 1
        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }

            //Helper checking if that module called for login
            AuthenticationResponseChallenge challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge != null)
            {
                string baseUri =
                    Request.Scheme +
                    Uri.SchemeDelimiter +
                    Request.Host +
                    Request.PathBase;

                string currentUri =
                    baseUri +
                    Request.Path +
                    Request.QueryString;

                string redirectUri =
                    baseUri +
                    Options.CallbackPath;

                AuthenticationProperties properties = challenge.Properties;
                if (string.IsNullOrEmpty(properties.RedirectUri))
                {
                    properties.RedirectUri = currentUri;
                }

                // OAuth2 10.12 CSRF
                GenerateCorrelationId(Options.CookieManager, properties);
                string protectedState = Options.StateDataFormat.Protect(properties);

                string state = properties.RedirectUri.Split('&')
                                     .Single(s => s.StartsWith("state="))
                                     .Substring(6);

                Context.Response.Cookies.Append(Constants.StateCookieName, protectedState);

                Options.StoreProtectedState = protectedState;
                Options.StoreState = state;

                string authorizationEndpoint =
                    Options.Endpoints.AuthorizationEndpoint +
                        "?redirect_url=" + Uri.EscapeDataString(redirectUri) +
                        "&state=" + Uri.EscapeDataString(state);

                var redirectContext = new EsiaBridgeApplyRedirectContext(
                    Context, Options,
                    properties, authorizationEndpoint);

                Options.Provider.ApplyRedirect(redirectContext);
            }

            return Task.FromResult<object>(null);
        }

        //step 2.0
        public override async Task<bool> InvokeAsync()
        {
            return await InvokeReplyPathAsync();
        }

        //step 2.1
        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;
            try
            {
                IReadableStringCollection query = Request.Query;

                IList<string> values = query.GetValues("error");
                if (values != null && values.Count >= 1)
                {
                    _logger.WriteVerbose("Remote server returned an error: " + Request.QueryString);
                    return new AuthenticationTicket(null, properties);
                }

                var protectedState = Options.CookieManager.GetRequestCookie(Context, Constants.StateCookieName);
                properties = Options.StateDataFormat.Unprotect(protectedState);
                if (properties == null)
                {
                    return null;
                }
                // OAuth2 10.12 CSRF
                if (!ValidateCorrelationId(Options.CookieManager, properties, _logger))
                {
                    return new AuthenticationTicket(null, properties);
                }
                var accessToken = Options.CookieManager.GetRequestCookie(Context, Constants.TokenCookieName);
                if (accessToken == null)
                {
                    return new AuthenticationTicket(null, properties);
                }
                string requestPrefix = Request.Scheme + "://" + Request.Host;
                string redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;

                var content = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("token", accessToken)
                });
                HttpResponseMessage userInfo = await _httpClient.PostAsync(Options.Endpoints.UserInfoEndpoint, content, Request.CallCancelled);
                userInfo.EnsureSuccessStatusCode();
                string text = await userInfo.Content.ReadAsStringAsync();
                JObject user = JObject.Parse(text);

                var context = new EsiaBridgeAuthenticatedContext(Context, user, accessToken);
                context.Identity = new ClaimsIdentity(Options.AuthenticationType, ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType);

                //Check State
                if (context.State != Options.StoreState)
                {
                    _logger.WriteWarning("Invalid return context state");
                    return new AuthenticationTicket(null, properties);
                }
                if (!string.IsNullOrEmpty(context.Id))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.Id, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.UserName))
                {
                    context.Identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, context.UserName, XmlSchemaString, Options.AuthenticationType));
                }               
                context.Properties = properties;
                await Options.Provider.Authenticated(context);

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception)
            {
                return new AuthenticationTicket(null, properties);
            }  
        }


        private async Task<bool> InvokeReplyPathAsync()
        {
            if (!Options.CallbackPath.HasValue || Options.CallbackPath != Request.Path) return false;

            var ticket = await AuthenticateAsync();
            if (ticket == null)
            {
                _logger.WriteWarning("Invalid return state, unable to redirect.");
                Response.StatusCode = 500;
                return true;
            }

            var context = new EsiaBridgeReturnEndpointContext(Context, ticket);
            context.SignInAsAuthenticationType = Options.SignInAsAuthenticationType;
            context.RedirectUri = ticket.Properties.RedirectUri;

            await Options.Provider.ReturnEndpoint(context);

            if (context.SignInAsAuthenticationType != null && context.Identity != null)
            {
                ClaimsIdentity grantIdentity = context.Identity;
                if (!string.Equals(grantIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                {
                    grantIdentity = new ClaimsIdentity(grantIdentity.Claims, context.SignInAsAuthenticationType, grantIdentity.NameClaimType, grantIdentity.RoleClaimType);
                }
                Context.Authentication.SignIn(context.Properties, grantIdentity);
            }

            if (!context.IsRequestCompleted && context.RedirectUri != null)
            {
                string redirectUri = context.RedirectUri;
                if (context.Identity == null)
                {
                    // add a redirect hint that sign-in failed in some way
                    redirectUri = WebUtilities.AddQueryString(redirectUri, "error", "access_denied");
                }
                Response.Redirect(redirectUri);
                context.RequestCompleted();
            }

            return context.IsRequestCompleted;
       
        }
    }
}