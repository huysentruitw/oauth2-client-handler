using System.Security.Claims;
using System.Threading.Tasks;
using System.Web.Http;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using Owin;

namespace OAuth2ClientHandler
{
    internal class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            app.UseOAuthAuthorizationServer(new OAuthAuthorizationServerOptions
                {
                    AllowInsecureHttp = true,
                    AuthorizeEndpointPath = new PathString("/authorize"),
                    TokenEndpointPath = new PathString("/token"),
                    Provider = new OAuthAuthorizationServerProvider
                    {
                        OnValidateClientAuthentication = (ctx) =>
                        {
                            string clientId, clientSecret;
                            if (ctx.TryGetBasicCredentials(out clientId, out clientSecret) &&
                                clientId.Equals("MyId") && clientSecret.Equals("MySecret"))
                                ctx.Validated(clientId);
                            else ctx.Rejected();
                            return Task.FromResult(0);
                        },
                        OnGrantClientCredentials = (ctx) =>
                        {
                            var identity = new ClaimsIdentity(OAuthDefaults.AuthenticationType);
                            var ticket = new AuthenticationTicket(identity, new AuthenticationProperties());
                            ctx.Validated(ticket);
                            return Task.FromResult(0);
                        },
                    }
                });

            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions
                {
                    AuthenticationMode = AuthenticationMode.Active
                });

            var config = new HttpConfiguration();
            config.MapHttpAttributeRoutes();
            app.UseWebApi(config);
        }
    }
}
