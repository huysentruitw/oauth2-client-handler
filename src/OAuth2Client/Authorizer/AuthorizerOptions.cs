using System;
using System.Net;

namespace OAuth2Client.Authorizer
{
    public class AuthorizerOptions
    {
        public Uri TokenEndpointUrl { get; set; }
        public Uri AuthorizeEndpointUrl { get; set; }
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public GrantType GrantType { get; set; }
        public Action<HttpStatusCode, string> OnError { get; set; }
    }
}
