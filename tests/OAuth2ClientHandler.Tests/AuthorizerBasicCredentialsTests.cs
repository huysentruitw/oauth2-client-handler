using Microsoft.Owin.Testing;
using NUnit.Framework;

namespace OAuth2ClientHandler.Tests
{
    [TestFixture]
    public class AuthorizerBasicCredentialsTests : AuthorizerTests
    {
        public AuthorizerBasicCredentialsTests() : base(CredentialsType.Basic)
        {
        }
    }
}