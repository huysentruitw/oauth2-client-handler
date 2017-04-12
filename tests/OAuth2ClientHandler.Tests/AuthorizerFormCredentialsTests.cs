using Microsoft.Owin.Testing;
using NUnit.Framework;

namespace OAuth2ClientHandler.Tests
{
    [TestFixture]
    public class AuthorizerFormCredentialsTests : AuthorizerTests
    {
        public AuthorizerFormCredentialsTests() : base(CredentialsType.Form)
        {
        }
    }
}