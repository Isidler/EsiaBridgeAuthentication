using System;
using Owin;

namespace EsiaBridgeAuthentication
{
    public static class EsiaBirdgeAuthenticationExtensions
    {
        //Добавлен допольнительный  контруктор EsiaBirdgeAuthenticationExtensions
        public static IAppBuilder UseEsiaBirdgeAuthentication(this IAppBuilder app, EsiaBridgeAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            app.Use(typeof(EsiaBirdgeAuthenticationMiddleware), app, options);
            return app;
        }


        public static IAppBuilder UseEsiaBirdgeAuthentication(this IAppBuilder app, string url)
        {
            Uri uri = new Uri(url);
            
            return UseEsiaBirdgeAuthentication(app,
                new EsiaBridgeAuthenticationOptions(schema: uri.Scheme, url: uri.Host, port: uri.Port.ToString()));
        }
    }
}