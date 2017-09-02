using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace EsiaBridgeAuthentication.Provider
{
    /// <summary>
    /// Provides context information to middleware providers.
    /// </summary>
    public class EsiaBridgeReturnEndpointContext : ReturnEndpointContext
    {
        // <summary>
        /// 
        /// </summary>
        /// <param name="context">OWIN environment</param>
        /// <param name="ticket">The authentication ticket</param>
        public EsiaBridgeReturnEndpointContext(IOwinContext context, AuthenticationTicket ticket)
            : base(context, ticket)
        {
        }
    }
}