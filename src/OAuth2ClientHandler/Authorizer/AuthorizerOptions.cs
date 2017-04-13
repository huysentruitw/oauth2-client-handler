using System;
using System.Collections.Generic;
using System.Net;

namespace OAuth2ClientHandler.Authorizer
{
    public class AuthorizerOptions
    {
        public Uri TokenEndpointUrl { get; set; }
        public Uri AuthorizeEndpointUrl { get; set; }
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public IEnumerable<string> Scope { get; set; }
        public GrantType GrantType { get; set; }
        public CredentialsType CredentialsType { get; set; }
        public Action<HttpStatusCode, string> OnError { get; set; }
    }
}
