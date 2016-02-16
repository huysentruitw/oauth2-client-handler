using System;
using Newtonsoft.Json;

namespace OAuth2Client.Authorizer
{
    internal class TokenResponse
    {
        [JsonProperty("access_token")]
        public string AccessToken { get; set; }
        [JsonProperty("refresh_token")]
        public string RefreshToken { get; set; }
        [JsonProperty("token_type")]
        public string TokenType { get; set; }
        [JsonProperty("expires_in")]
        public int ExpiresInSeconds { private get; set; }

        public TimeSpan ExpiresIn { get { return TimeSpan.FromSeconds(ExpiresInSeconds); } }
    }
}
