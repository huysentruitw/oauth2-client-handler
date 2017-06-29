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
                            string clientId;
                            if (HasValidBasicCredentials(ctx, out clientId)) ctx.Validated(clientId);
                            else if (HasValidFormCredentials(ctx, out clientId)) ctx.Validated(clientId);
                            else ctx.Rejected();
                            return Task.FromResult(0);
                        },
                        OnGrantClientCredentials = (ctx) =>
                        {
                            if (ctx.Scope.Contains("testscope"))
                            {
                                ctx.SetError("testscope_ok");
                                return Task.FromResult(0);
                            }
                            var identity = new ClaimsIdentity(OAuthDefaults.AuthenticationType);
                            var ticket = new AuthenticationTicket(identity, new AuthenticationProperties());
                            ctx.Validated(ticket);
                            return Task.FromResult(0);
                        },
                        OnGrantResourceOwnerCredentials = (ctx) =>
                        {
                            if (ctx.Scope.Contains("othertestscope"))
                            {
                                ctx.SetError("othertestscope_ok");
                                return Task.FromResult(0);
                            }
                            if (!ctx.UserName.Equals("MyUsername") || !ctx.Password.Equals("MyPassword"))
                            {
                                ctx.SetError("invalid_grant");
                                return Task.FromResult(0);
                            }
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

        private static bool HasValidBasicCredentials(OAuthValidateClientAuthenticationContext ctx, out string clientId)
        {
            string clientSecret;
            return ctx.TryGetBasicCredentials(out clientId, out clientSecret)
                   && clientId.Equals("MyId")
                   && clientSecret.Equals("MySecret");
        }

        private static bool HasValidFormCredentials(OAuthValidateClientAuthenticationContext ctx, out string clientId)
        {
            string clientSecret;
            return ctx.TryGetFormCredentials(out clientId, out clientSecret)
                   && clientId.Equals("MyFormId")
                   && clientSecret.Equals("MyFormSecret");
        }
    }
}
