using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using OAuth2ClientHandler.Authorizer;

namespace OAuth2ClientHandler
{
    public class OAuthHttpHandler : DelegatingHandler
    {
        private readonly SemaphoreSlim _semaphore = new SemaphoreSlim(1, 1);
        private readonly IAuthorizer _authorizer;
        private TokenResponse _tokenResponse;

        public string AccessToken
        {
            get
            {
                if(_tokenResponse == null)
                    _tokenResponse = GetTokenResponse(CancellationToken.None).Result;
                return _tokenResponse.AccessToken;
            }
        }

        public OAuthHttpHandler(OAuthHttpHandlerOptions options, Func<HttpClient> createAuthorizerHttpClient = null)
        {
            if (options == null)
                throw new ArgumentNullException(nameof(options));

            InnerHandler = options.InnerHandler ?? new HttpClientHandler();

            _authorizer = new Authorizer.Authorizer(options.AuthorizerOptions,
                createAuthorizerHttpClient ?? CreateHttpClient);
        }

        private HttpClient CreateHttpClient() => new HttpClient(InnerHandler, false);

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);

            if (disposing)
                InnerHandler?.Dispose();
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            if (request.Headers.Authorization == null)
            {
                var tokenResponse = await GetTokenResponse(cancellationToken);
                if (tokenResponse != null)
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokenResponse.AccessToken);
            }

            var response = await base.SendAsync(request, cancellationToken);

            if (response.StatusCode != HttpStatusCode.Unauthorized) return response;
            {
                var tokenResponse = await RefreshTokenResponse(cancellationToken);
                if (tokenResponse != null)
                {
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokenResponse.AccessToken);
                    response = await base.SendAsync(request, cancellationToken);
                }
            }

            return response;
        }

        private async Task<TokenResponse> GetTokenResponse(CancellationToken cancellationToken)
        {
            try
            {
                _semaphore.Wait(cancellationToken);
                if (cancellationToken.IsCancellationRequested) return null;
                _tokenResponse = _tokenResponse ?? await _authorizer.GetToken(cancellationToken);
                return _tokenResponse;
            }
            finally
            {
                _semaphore.Release();
            }
        }

        private async Task<TokenResponse> RefreshTokenResponse(CancellationToken cancellationToken)
        {
            try
            {
                _semaphore.Wait(cancellationToken);
                if (cancellationToken.IsCancellationRequested) return null;
                _tokenResponse = await _authorizer.GetToken(cancellationToken);
                return _tokenResponse;
            }
            finally
            {
                _semaphore.Release();
            }
        }
    }
}