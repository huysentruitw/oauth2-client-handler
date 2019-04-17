using System.Net.Http;
using OAuth2ClientHandler.Authorizer;

namespace OAuth2ClientHandler
{
    public sealed class OAuthHttpHandlerOptions
    {
        public AuthorizerOptions AuthorizerOptions { get; set; }
        public HttpMessageHandler InnerHandler { get; set; }

        public OAuthHttpHandlerOptions()
        {
            AuthorizerOptions = new AuthorizerOptions();
        }
    }
}
