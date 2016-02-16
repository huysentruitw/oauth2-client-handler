using System;
using System.Net;
using System.Threading.Tasks;
using Microsoft.Owin.Testing;
using NUnit.Framework;
using OAuth2ClientHandler.Authorizer;

namespace OAuth2ClientHandler.Tests
{
    [TestFixture]
    public class AuthorizerTests
    {
        private TestServer server;

        [TestFixtureSetUp]
        public void FixtureSetUp()
        {
            server = TestServer.Create<Startup>();
        }

        [TestFixtureTearDown]
        public void FixtureTearDown()
        {
            server.Dispose();
        }

        [Test]
        public async Task GetAccessToken_ValidClientCredentials_ReturnsValidAccessToken()
        {
            var options = new AuthorizerOptions
            {
                AuthorizeEndpointUrl = new Uri("http://localhost/authorize"),
                TokenEndpointUrl = new Uri("http://localhost/token"),
                ClientId = "MyId",
                ClientSecret = "MySecret",
                GrantType = GrantType.ClientCredentials
            };

            var authorizer = new Authorizer.Authorizer(options, () => server.HttpClient);
            var result = await authorizer.GetAccessToken();
            Assert.NotNull(result.AccessToken);
        }

        [Test]
        public void GetAccessToken_InvalidClientCredentialsWithoutOnErrorCallback_ThrowsProtocolException()
        {
            var options = new AuthorizerOptions
            {
                AuthorizeEndpointUrl = new Uri("http://localhost/authorize"),
                TokenEndpointUrl = new Uri("http://localhost/token"),
                ClientId = "WrongId",
                ClientSecret = "WrongSecret",
                GrantType = GrantType.ClientCredentials
            };

            var authorizer = new Authorizer.Authorizer(options, () => server.HttpClient);
            
            var ex = Assert.Throws<ProtocolException>(async () => await authorizer.GetAccessToken());
            
            Assert.IsTrue(ex.Message.Contains("invalid_client"));
            Assert.AreEqual(HttpStatusCode.BadRequest, ex.StatusCode);
        }

        [Test]
        public async Task GetAccessToken_InvalidClientCredentialsWithOnErrorCallback_OnErrorGetsCalled()
        {
            HttpStatusCode errorStatusCode = HttpStatusCode.Unused;
            string errorMessage = string.Empty;

            var options = new AuthorizerOptions
            {
                AuthorizeEndpointUrl = new Uri("http://localhost/authorize"),
                TokenEndpointUrl = new Uri("http://localhost/token"),
                ClientId = "WrongId",
                ClientSecret = "WrongSecret",
                GrantType = GrantType.ClientCredentials,
                OnError = (statusCode, message) =>
                {
                    errorStatusCode = statusCode;
                    errorMessage = message;
                }
            };

            var authorizer = new Authorizer.Authorizer(options, () => server.HttpClient);

            await authorizer.GetAccessToken();

            Assert.IsTrue(errorMessage.Contains("invalid_client"));
            Assert.AreEqual(HttpStatusCode.BadRequest, errorStatusCode);
        }

        [Test]
        public void GetAccessToken_InvalidTokenEndpointUrl_ThrowsProtocolException()
        {
            var options = new AuthorizerOptions
            {
                AuthorizeEndpointUrl = new Uri("http://localhost/authorize"),
                TokenEndpointUrl = new Uri("http://localhost/invalid"),
                ClientId = "MyId",
                ClientSecret = "MySecret",
                GrantType = GrantType.ClientCredentials
            };

            var authorizer = new Authorizer.Authorizer(options, () => server.HttpClient);
            var ex = Assert.Throws<ProtocolException>(async () => await authorizer.GetAccessToken());
            Assert.AreEqual(HttpStatusCode.NotFound, ex.StatusCode);
        }
    }
}
