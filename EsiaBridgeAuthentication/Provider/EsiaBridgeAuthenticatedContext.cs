using System;
using System.Globalization;
using System.Security.Claims;
using System.Xml;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace EsiaBridgeAuthentication.Provider
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class EsiaBridgeAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="EsiaBridgeAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized user</param>
        /// <param name="accessToken">VK Access token</param>
        public EsiaBridgeAuthenticatedContext(IOwinContext context, JObject user, string accessToken)
            : base(context)
        {
            User = user;
            AccessToken = accessToken;

            Id = TryGetValue(user, "oid");
            var firstName = TryGetValue(user, "firstName");
            var lastName = TryGetValue(user, "lastName");
            UserName = firstName + " " + lastName;
            State = TryGetValue(user, "state");

        }
        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        /// <remarks>
        /// Contains the Esia-Bridge user obtained from the User Info endpoint. By default this is {your Esia-Bridge server url}/blitz/bridge/user but it can be
        /// overridden in the options
        /// </remarks>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the Esia-Bridge access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the Esia-Bridge State
        /// </summary>
        public string State { get; private set; }

        /// <summary>
        /// Gets the Esia-Bridge user ID
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// Gets the user's name
        /// </summary>
        public string UserName { get; private set; }

        /// <summary>
        /// Gets the <see cref="ClaimsIdentity"/> representing the user
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }

        private static string TryGetValue(JObject user, string propertyName)
        {
            JToken value;
            return user.TryGetValue(propertyName, out value) ? value.ToString() : null;
        }
    }
}
