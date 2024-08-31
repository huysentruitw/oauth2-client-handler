using System.Threading;
using System.Threading.Tasks;

namespace OAuth2ClientHandler.Authorizer
{
    internal interface IAuthorizer
    {
        Task<TokenData> GetToken(CancellationToken? cancellationToken = null);
    }
}
