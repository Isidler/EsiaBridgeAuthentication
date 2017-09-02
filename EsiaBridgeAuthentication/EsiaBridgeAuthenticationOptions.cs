using EsiaBridgeAuthentication.Provider;
using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Security;
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Net.Http;

namespace EsiaBridgeAuthentication
{

    public class EsiaBridgeAuthenticationOptions : AuthenticationOptions
    {
        private const string DefaultCallbackPath = "/signin-esia";
        private const string DefaultMode = "online";

        public EsiaBridgeAuthenticationEndpoints Endpoints { get; set; }
        public string SignInAsAuthenticationType { get; set; }

        /// <summary>
        /// Gets or sets the a pinned certificate validator to use to validate the endpoints used
        /// in back channel communications belong to Esia-Bridge.
        /// </summary>
        /// <value>
        /// The pinned certificate validator.
        /// </value>
        /// <remarks>If this property is null then the default certificate checks are performed,
        /// validating the subject name and if the signing chain is a trusted party.</remarks>
        public ICertificateValidator BackchannelCertificateValidator { get; set; }

        /// <summary>
        /// Gets or sets timeout value in milliseconds for back channel communications with Esia-Bridge.
        /// </summary>
        /// <value>
        /// The back channel timeout in milliseconds.
        /// </value>
        public TimeSpan BackchannelTimeout { get; set; }

        /// <summary>
        /// The HttpMessageHandler used to communicate with Esia-Bridge.
        /// This cannot be set at the same time as BackchannelCertificateValidator unless the value 
        /// can be downcast to a WebRequestHandler.
        /// </summary>
        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        /// <summary>
        /// Get or sets the text that the user can display on a sign in user interface.
        /// </summary>
        public string Caption
        {
            get { return Description.Caption; }
            set { Description.Caption = value; }
        }

        /// <summary>
        /// The request path within the application's base path where the user-agent will be returned.
        /// The middleware will process this request when it arrives.
        /// Default value is "/signin-esia".
        /// </summary>
        public PathString CallbackPath { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="IEsiaBridgeAuthenticationProvider"/> used to handle authentication events.
        /// </summary>
        public IEsiaBridgeAuthenticationProvider Provider { get; set; }

        /// <summary>
        /// Gets or sets the type used to secure data handled by the middleware.
        /// </summary>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        /// <summary>
        /// Gets or sets the site redirect url after login 
        /// </summary>
        public string StoreProtectedState { get; set; }

        public string StoreState { get; set; }

        /// <summary>
        /// An abstraction for reading and setting cookies during the authentication process.
        /// </summary>
        public ICookieManager CookieManager { get; set; }
        public EsiaBridgeAuthenticationOptions(string schema, string url, string port) : base(Constants.DefaultAuthenticationType)
        {
            Description.Caption = Constants.DefaultAuthenticationType;
            CookieManager = new CookieManager();
            Caption = Constants.DefaultAuthenticationType;
            CallbackPath = new PathString(DefaultCallbackPath);
            AuthenticationMode = AuthenticationMode.Passive;
            BackchannelTimeout = TimeSpan.FromSeconds(60);

            //StateDataFormat = new EsiaBridgeDataProtector();

            Endpoints = new EsiaBridgeAuthenticationEndpoints
            {
                AuthorizationEndpoint = String.Format("{0}://{1}:{2}/blitz/bridge/entrance", schema, url, port),
                UserInfoEndpoint = String.Format("{0}://{1}:{2}/blitz/bridge/user", schema, url, port)
            };
        }
    }
}