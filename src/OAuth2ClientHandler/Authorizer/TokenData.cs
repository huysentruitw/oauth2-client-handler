using System;

namespace OAuth2ClientHandler.Authorizer
{
    public sealed class TokenData
    {
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public string TokenType { get; set; }
        public int ExpiresInSeconds { private get; set; }

        public TimeSpan ExpiresIn => TimeSpan.FromSeconds(ExpiresInSeconds);
    }
}
