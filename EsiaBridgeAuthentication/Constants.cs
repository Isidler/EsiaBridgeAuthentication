using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EsiaBridgeAuthentication
{
    public static class Constants
    {
        public const string DefaultAuthenticationType = "EsiaBridge";
        internal const string AuthorizationEndpoint = "https://www.facebook.com/v2.8/dialog/oauth";
        internal const string UserInformationEndpoint = "https://graph.facebook.com/v2.8/me";
        internal const string StateCookieName = "ProtectedState";
        internal const string TokenCookieName = "tokenSCS";
    }
}
