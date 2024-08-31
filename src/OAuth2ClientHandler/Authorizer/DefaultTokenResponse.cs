using System.Runtime.Serialization;

namespace OAuth2ClientHandler.Authorizer
{
    [DataContract]
    internal sealed class DefaultTokenResponse
    {
        [DataMember(Name = "access_token")]
        public string AccessToken { get; set; }
        [DataMember(Name = "refresh_token")]
        public string RefreshToken { get; set; }
        [DataMember(Name = "token_type")]
        public string TokenType { get; set; }
        [DataMember(Name = "expires_in")]
        public int ExpiresInSeconds { get; set; }
    }
}
