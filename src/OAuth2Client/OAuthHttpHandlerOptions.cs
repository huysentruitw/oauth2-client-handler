using System.Net.Http;
using OAuth2Client.Authorizer;

namespace OAuth2Client
{
    public class OAuthHttpHandlerOptions
    {
        public AuthorizerOptions AuthorizerOptions { get; set; }
        public HttpMessageHandler InnerHandler { get; set; }

        public OAuthHttpHandlerOptions()
        {
            AuthorizerOptions = new AuthorizerOptions();
        }
    }
}
