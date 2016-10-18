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
        private const string AuthorizationHeaderName = "Authorization";
        private OAuthHttpHandlerOptions options;
        private bool ownsHandler = false;
        private IAuthorizer authorizer;
        internal TokenResponse tokenResponse;
        private SemaphoreSlim semaphore = new SemaphoreSlim(1, 1);

        public OAuthHttpHandler(OAuthHttpHandlerOptions options)
        {
            if (options == null) throw new ArgumentNullException("authorizer");
            this.options = options;
            InnerHandler = options.InnerHandler ?? new HttpClientHandler();
            ownsHandler = options.InnerHandler == null;
            authorizer = new Authorizer.Authorizer(options.AuthorizerOptions, () => new HttpClient(InnerHandler, false));
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);

            if (disposing && ownsHandler)
                InnerHandler.Dispose();
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Headers.Authorization == null)
            {
                var tokenResponse = await GetTokenResponse(cancellationToken);
                if (tokenResponse != null)
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokenResponse.AccessToken);
            }

            var response = await base.SendAsync(request, cancellationToken);

            if (response.StatusCode == HttpStatusCode.Unauthorized)
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

        internal async Task<TokenResponse> GetTokenResponse(CancellationToken cancellationToken)
        {
            try
            {
                semaphore.Wait(cancellationToken);
                if (cancellationToken.IsCancellationRequested) return null;
                tokenResponse = tokenResponse ?? await authorizer.GetToken(cancellationToken);
                return tokenResponse;
            }
            finally
            {
                semaphore.Release();
            }
        }

        internal async Task<TokenResponse> RefreshTokenResponse(CancellationToken cancellationToken)
        {
            try
            {
                semaphore.Wait(cancellationToken);
                if (cancellationToken.IsCancellationRequested) return null;
                tokenResponse = await authorizer.RefreshToken(tokenResponse, cancellationToken);
                return tokenResponse;
            }
            catch (Exception e)
            {
                throw e;
            }
            finally
            {
                semaphore.Release();
            }
        }
    }
}
