using System.Threading;
using System.Threading.Tasks;

namespace OAuth2Client.Authorizer
{
    internal interface IAuthorizer
    {
        Task<TokenResponse> GetAccessToken(CancellationToken? cancellationToken = null);
    }
}
