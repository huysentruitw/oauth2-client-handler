using System.Threading;
using System.Threading.Tasks;

namespace OAuth2ClientHandler.Authorizer
{
    internal interface IAuthorizer
    {
        Task<TokenResponse> GetAccessToken(CancellationToken? cancellationToken = null);
    }
}
