using OAuth2ClientHandler.Authorizer;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace OAuth2ClientHandler
{
    public class OAuthHttpClient : HttpClient
    {
        public OAuthHttpHandler oAuthHttpHandler { get; set; }
        public TokenResponse tokenResponse { 
            get {
                return oAuthHttpHandler.tokenResponse;
            } 
        }

        private OAuthHttpClient(HttpMessageHandler handler, bool disposeHandler)
            : base(handler, disposeHandler)
        {

        }
        private OAuthHttpClient(HttpMessageHandler handler)
            : base(handler)
        {

        }

        private OAuthHttpClient()
            : base()
        {

        }

        public async Task<TokenResponse> GetTokenResponse(CancellationToken cancellationToken)
        {
            return await oAuthHttpHandler.GetTokenResponse(cancellationToken);
        }

        public async Task<TokenResponse> RefreshTokenResponse(CancellationToken cancellationToken)
        {
            return await oAuthHttpHandler.RefreshTokenResponse(cancellationToken);
        }

        public static OAuthHttpClient Factory(OAuthHttpHandlerOptions options)
        {
            var oAuthHttpHandler = new OAuthHttpHandler(options);
            var oAuthHttpClient = new OAuthHttpClient(oAuthHttpHandler);
            oAuthHttpClient.oAuthHttpHandler = oAuthHttpHandler;
            return oAuthHttpClient;
        }


    }
}
