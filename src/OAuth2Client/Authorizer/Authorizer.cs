using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace OAuth2Client.Authorizer
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

        public async Task<TokenResponse> GetAccessToken(CancellationToken? cancellationToken = null)
        {
            cancellationToken = cancellationToken ?? new CancellationToken(false);
            switch (options.GrantType)
            {
                case GrantType.ClientCredentials:
                    return await GetAccessTokenWithClientCredentials(cancellationToken.Value);
                default:
                    throw new NotSupportedException(string.Format("Requested grant type '{0}' is not supported", options.GrantType));
            }
        }

        private async Task<TokenResponse> GetAccessTokenWithClientCredentials(CancellationToken cancellationToken)
        {
            if (options.TokenEndpointUrl == null) throw new ArgumentNullException("TokenEndpointUrl");
            if (!options.TokenEndpointUrl.IsAbsoluteUri) throw new ArgumentException("TokenEndpointUrl must be absolute");
            using (var client = this.createHttpClient())
            {
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", GetBasicAuthorizationHeaderValue());
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                var content = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string, string>("grant_type", "client_credentials"),
                });

                var response = await client.PostAsync(options.TokenEndpointUrl, content, cancellationToken);
                if (cancellationToken.IsCancellationRequested) return null;
                var responseContent = await response.Content.ReadAsStringAsync();

                if (!response.IsSuccessStatusCode)
                    RaiseProtocolException(response.StatusCode, responseContent);

                return JsonConvert.DeserializeObject<TokenResponse>(responseContent);
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
