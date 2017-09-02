using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EsiaBridgeAuthentication
{
    public class EsiaBridgeAuthenticationEndpoints
    {
        /// <summary>
        /// Endpoint which is used to redirect users to request Esia access and get access token
        /// </summary>
        public string AuthorizationEndpoint { get; set; }


        /// <summary>
        /// Endpoint which is used to obtain user information after authentication
        /// </summary>
        public string UserInfoEndpoint { get; set; }
    }
}
