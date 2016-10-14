using System.Threading;
using System.Threading.Tasks;

namespace OAuth2ClientHandler.Authorizer
{
    internal interface IAuthorizer
    {
        Task<TokenResponse> GetToken(CancellationToken? cancellationToken = null);

        Task<TokenResponse> RefreshToken(TokenResponse tokenResponse, CancellationToken? cancellationToken = null);
    }
}
