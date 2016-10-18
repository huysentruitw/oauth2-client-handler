using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace OAuth2ClientHandler.Authorizer
{
    internal class Authorizer : IAuthorizer
    {
        private AuthorizerOptions options;
        private Func<HttpClient> createHttpClient;

        internal Authorizer(AuthorizerOptions options, Func<HttpClient> createHttpClient)
        {
            if (options == null) throw new ArgumentNullException("options");
            if (createHttpClient == null) throw new ArgumentNullException("createHttpClient");
            this.options = options;
            this.createHttpClient = createHttpClient;
        }

        public Authorizer(AuthorizerOptions options)
            : this(options, () => new HttpClient())
        {
        }

        public async Task<TokenResponse> GetToken(CancellationToken? cancellationToken = null)
        {
            cancellationToken = cancellationToken ?? new CancellationToken(false);
            switch (options.GrantType)
            {
                case GrantType.ClientCredentials:
                    return await GetTokenWithClientCredentials(cancellationToken.Value);
                case GrantType.ResourceOwnerPasswordCredentials:
                    return await GetTokenWithResourceOwnerPasswordCredentials(cancellationToken.Value);
                default:
                    throw new NotSupportedException(string.Format("Requested grant type '{0}' is not supported", options.GrantType));
            }
        }

        public async Task<TokenResponse> RefreshToken(TokenResponse tokenResponse, CancellationToken? cancellationToken = null)
        {
            cancellationToken = cancellationToken ?? new CancellationToken(false);
            switch (options.GrantType)
            {
                case GrantType.ClientCredentials:
                    return await RefreshTokenWithClientCredentials(tokenResponse, cancellationToken.Value);
                case GrantType.ResourceOwnerPasswordCredentials:
                    return await GetTokenWithResourceOwnerPasswordCredentials(cancellationToken.Value);
                default:
                    throw new NotSupportedException(string.Format("Requested grant type '{0}' is not supported", options.GrantType));
            }
        }

        private async Task<TokenResponse> GetTokenWithClientCredentials(CancellationToken cancellationToken)
        {
            if (options.TokenEndpointUrl == null) throw new ArgumentNullException("TokenEndpointUrl");
            if (!options.TokenEndpointUrl.IsAbsoluteUri) throw new ArgumentException("TokenEndpointUrl must be absolute");
            using (var client = this.createHttpClient())
            {
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", GetBasicAuthorizationHeaderValue());
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                var properties = new Dictionary<string, string> { { "grant_type", "client_credentials" } };
                if (options.Scope != null) properties.Add("scope", string.Join(" ", options.Scope));

                var content = new FormUrlEncodedContent(properties);

                var response = await client.PostAsync(options.TokenEndpointUrl, content, cancellationToken);
                if (cancellationToken.IsCancellationRequested) return null;

                if (!response.IsSuccessStatusCode)
                {
                    RaiseProtocolException(response.StatusCode, await response.Content.ReadAsStringAsync());
                    return null;
                }

                return JsonConvert.DeserializeObject<TokenResponse>(await response.Content.ReadAsStringAsync());
            }
        }

        private async Task<TokenResponse> RefreshTokenWithClientCredentials(TokenResponse tokenResponse, CancellationToken cancellationToken)
        {
            if (options.TokenEndpointUrl == null) throw new ArgumentNullException("TokenEndpointUrl");
            if (tokenResponse == null || tokenResponse.RefreshToken == null) return null;
            if (!options.TokenEndpointUrl.IsAbsoluteUri) throw new ArgumentException("TokenEndpointUrl must be absolute");
            using (var client = this.createHttpClient())
            {
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", GetBasicAuthorizationHeaderValue());
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                var properties = new Dictionary<string, string> { 
                    { "grant_type", "refresh_token" },
                    {"refresh_token", tokenResponse.RefreshToken }
                };
                if (options.Scope != null) properties.Add("scope", string.Join(" ", options.Scope));

                var content = new FormUrlEncodedContent(properties);

                var response = await client.PostAsync(options.TokenEndpointUrl, content, cancellationToken);
                if (cancellationToken.IsCancellationRequested) return null;

                if (!response.IsSuccessStatusCode)
                {
                    RaiseProtocolException(response.StatusCode, await response.Content.ReadAsStringAsync());
                    return null;
                }

                return JsonConvert.DeserializeObject<TokenResponse>(await response.Content.ReadAsStringAsync());
            }
        }

        private async Task<TokenResponse> GetTokenWithResourceOwnerPasswordCredentials(CancellationToken cancellationToken)
        {
            if (options.TokenEndpointUrl == null) throw new ArgumentNullException("TokenEndpointUrl");
            if (!options.TokenEndpointUrl.IsAbsoluteUri) throw new ArgumentException("TokenEndpointUrl must be absolute");
            if (options.Username == null) throw new ArgumentNullException("Username");
            if (options.Password == null) throw new ArgumentNullException("Password");
            using (var client = this.createHttpClient())
            {
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", GetBasicAuthorizationHeaderValue());
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                var properties = new Dictionary<string, string>
                {
                    { "grant_type", "password" },
                    { "username", options.Username },
                    { "password", options.Password }
                };
                if (options.Scope != null) properties.Add("scope", string.Join(" ", options.Scope));

                var content = new FormUrlEncodedContent(properties);

                var response = await client.PostAsync(options.TokenEndpointUrl, content, cancellationToken);
                if (cancellationToken.IsCancellationRequested) return null;

                if (!response.IsSuccessStatusCode)
                {
                    RaiseProtocolException(response.StatusCode, await response.Content.ReadAsStringAsync());
                    return null;
                }

                return JsonConvert.DeserializeObject<TokenResponse>(await response.Content.ReadAsStringAsync());
            }
        }

        private string GetBasicAuthorizationHeaderValue()
        {
            if (options.ClientId == null) throw new ArgumentNullException("ClientId");
            if (options.ClientSecret == null) throw new ArgumentNullException("ClientSecret");
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(string.Format("{0}:{1}", options.ClientId, options.ClientSecret)));
        }

        private void RaiseProtocolException(HttpStatusCode statusCode, string message)
        {
            if (options.OnError != null) options.OnError(statusCode, message);
            else throw new ProtocolException(statusCode, message);
        }
    }
}
