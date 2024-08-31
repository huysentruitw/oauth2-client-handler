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
    internal sealed class Authorizer : IAuthorizer
    {
        private readonly AuthorizerOptions _options;
        private readonly Func<HttpClient> _createHttpClient;

        internal Authorizer(AuthorizerOptions options, Func<HttpClient> createHttpClient)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
            _createHttpClient = createHttpClient ?? throw new ArgumentNullException(nameof(createHttpClient));
        }

        public Authorizer(AuthorizerOptions options)
            : this(options, () => new HttpClient())
        {
        }

        public async Task<TokenData> GetToken(CancellationToken? cancellationToken = null)
        {
            cancellationToken = cancellationToken ?? new CancellationToken(false);
            switch (_options.GrantType)
            {
                case GrantType.ClientCredentials:
                    return await GetTokenWithClientCredentials(cancellationToken.Value);
                case GrantType.ResourceOwnerPasswordCredentials:
                    return await GetTokenWithResourceOwnerPasswordCredentials(cancellationToken.Value);
                default:
                    throw new NotSupportedException($"Requested grant type '{_options.GrantType}' is not supported");
            }
        }

        private Task<TokenData> GetTokenWithClientCredentials(CancellationToken cancellationToken)
        {
            if (_options.TokenEndpointUrl == null) throw new ArgumentNullException(nameof(_options.TokenEndpointUrl));
            if (!_options.TokenEndpointUrl.IsAbsoluteUri) throw new ArgumentException("Must be absolute", nameof(_options.TokenEndpointUrl));

            var properties = new Dictionary<string, string>
            {
                { "grant_type", "client_credentials" }
            };

            return GetToken(properties, cancellationToken);
        }

        private Task<TokenData> GetTokenWithResourceOwnerPasswordCredentials(CancellationToken cancellationToken)
        {
            if (_options.TokenEndpointUrl == null) throw new ArgumentNullException(nameof(_options.TokenEndpointUrl));
            if (!_options.TokenEndpointUrl.IsAbsoluteUri) throw new ArgumentException("Must be absolute", nameof(_options.TokenEndpointUrl));
            if (_options.Username == null) throw new ArgumentNullException(nameof(_options.Username));
            if (_options.Password == null) throw new ArgumentNullException(nameof(_options.Password));

            var properties = new Dictionary<string, string>
            {
                { "grant_type", "password" },
                { "username", _options.Username },
                { "password", _options.Password }
            };

            return GetToken(properties, cancellationToken);
        }

        private async Task<TokenData> GetToken(IDictionary<string, string> properties, CancellationToken cancellationToken)
        {
            using (var client = _createHttpClient())
            {
                switch (_options.CredentialTransportMethod)
                {
                    case CredentialTransportMethod.BasicAuthenticationCredentials:
                        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", GetBasicAuthorizationHeaderValue());
                        break;
                    case CredentialTransportMethod.FormAuthenticationCredentials:
                        properties.Add("client_id", _options.ClientId);
                        properties.Add("client_secret", _options.ClientSecret);
                        break;
                    default:
                        throw new ArgumentOutOfRangeException();
                }

                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                if (_options.Scope != null) properties.Add("scope", string.Join(" ", _options.Scope));

                var content = new FormUrlEncodedContent(properties);

                var response = await client.PostAsync(_options.TokenEndpointUrl, content, cancellationToken);
                if (cancellationToken.IsCancellationRequested) return null;

                if (!response.IsSuccessStatusCode)
                {
                    RaiseProtocolException(response.StatusCode, await response.Content.ReadAsStringAsync());
                    return null;
                }

                if (_options.TokenDataDeserializer != null)
                    return _options.TokenDataDeserializer(await response.Content.ReadAsStreamAsync());
                else
                    return DefaultTokenDataDeserializer(await response.Content.ReadAsStreamAsync());
            }
        }

        private string GetBasicAuthorizationHeaderValue()
        {
            if (_options.ClientId == null) throw new ArgumentNullException(nameof(_options.ClientId));
            if (_options.ClientSecret == null) throw new ArgumentNullException(nameof(_options.ClientSecret));
            return Convert.ToBase64String(Encoding.UTF8.GetBytes($"{_options.ClientId}:{_options.ClientSecret}"));
        }

        private void RaiseProtocolException(HttpStatusCode statusCode, string message)
        {
            if (_options.OnError != null) _options.OnError(statusCode, message);
            else throw new ProtocolException(statusCode, message);
        }

        private TokenData DefaultTokenDataDeserializer(System.IO.Stream stream)
        {
            var serializer = new DataContractJsonSerializer(typeof(DefaultTokenResponse));
            var tokenResponse = serializer.ReadObject(stream) as DefaultTokenResponse;
            return new TokenData()
            {
                AccessToken = tokenResponse.AccessToken,
                TokenType = tokenResponse.TokenType,
                RefreshToken = tokenResponse.RefreshToken,
                ExpiresInSeconds = tokenResponse.ExpiresInSeconds
            };
        }
    }
}
