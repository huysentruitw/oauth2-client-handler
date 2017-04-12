using System;
using System.Net;
using System.Threading.Tasks;
using Microsoft.Owin.Testing;
using NUnit.Framework;
using OAuth2ClientHandler.Authorizer;

namespace OAuth2ClientHandler.Tests
{
    public abstract class AuthorizerTests : IDisposable
    {
        private readonly CredentialsType credentialsType;
        private readonly TestServer server;

        protected AuthorizerTests(CredentialsType credentialsType)
        {
            this.credentialsType = credentialsType;
            this.server = TestServer.Create(new Startup(credentialsType).Configuration);
        }

        public void Dispose()
        {
            server.Dispose();
        }

        [Test]
        public async Task GetToken_ValidClientCredentials_ReturnsValidAccessToken()
        {
            var options = new AuthorizerOptions
            {
                AuthorizeEndpointUrl = new Uri("http://localhost/authorize"),
                TokenEndpointUrl = new Uri("http://localhost/token"),
                ClientId = "MyId",
                ClientSecret = "MySecret",
                GrantType = GrantType.ClientCredentials,
                CredentialsType = credentialsType
            };

            var authorizer = new Authorizer.Authorizer(options, () => server.HttpClient);
            var result = await authorizer.GetToken();
            Assert.NotNull(result.AccessToken);
        }

        [Test]
        public void GetToken_InvalidClientCredentialsWithoutOnErrorCallback_ThrowsProtocolException()
        {
            var options = new AuthorizerOptions
            {
                AuthorizeEndpointUrl = new Uri("http://localhost/authorize"),
                TokenEndpointUrl = new Uri("http://localhost/token"),
                ClientId = "WrongId",
                ClientSecret = "WrongSecret",
                GrantType = GrantType.ClientCredentials,
                CredentialsType = credentialsType
            };

            var authorizer = new Authorizer.Authorizer(options, () => server.HttpClient);
            
            var ex = Assert.Throws<ProtocolException>(async () => await authorizer.GetToken());
            
            Assert.IsTrue(ex.Message.Contains("invalid_client"));
            Assert.AreEqual(HttpStatusCode.BadRequest, ex.StatusCode);
        }

        [Test]
        public async Task GetToken_InvalidClientCredentialsWithOnErrorCallback_OnErrorGetsCalled()
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
                CredentialsType = credentialsType,
                OnError = (statusCode, message) =>
                {
                    errorStatusCode = statusCode;
                    errorMessage = message;
                }
            };

            var authorizer = new Authorizer.Authorizer(options, () => server.HttpClient);

            await authorizer.GetToken();

            Assert.IsTrue(errorMessage.Contains("invalid_client"));
            Assert.AreEqual(HttpStatusCode.BadRequest, errorStatusCode);
        }

        [Test]
        public void GetToken_InvalidTokenEndpointUrl_ThrowsProtocolException()
        {
            var options = new AuthorizerOptions
            {
                AuthorizeEndpointUrl = new Uri("http://localhost/authorize"),
                TokenEndpointUrl = new Uri("http://localhost/invalid"),
                ClientId = "MyId",
                ClientSecret = "MySecret",
                GrantType = GrantType.ClientCredentials,
                CredentialsType = credentialsType
            };

            var authorizer = new Authorizer.Authorizer(options, () => server.HttpClient);
            var ex = Assert.Throws<ProtocolException>(async () => await authorizer.GetToken());
            Assert.AreEqual(HttpStatusCode.NotFound, ex.StatusCode);
        }

        [Test]
        public void GetToken_ClientCredentialsWithScope_ShouldRequestScope()
        {
            var options = new AuthorizerOptions
            {
                AuthorizeEndpointUrl = new Uri("http://localhost/authorize"),
                TokenEndpointUrl = new Uri("http://localhost/token"),
                ClientId = "MyId",
                ClientSecret = "MySecret",
                GrantType = GrantType.ClientCredentials,
                CredentialsType = credentialsType,
                Scope = new[] { "testscope" }
            };

            var authorizer = new Authorizer.Authorizer(options, () => server.HttpClient);
            var ex = Assert.Throws<ProtocolException>(async () => await authorizer.GetToken());
            Assert.IsTrue(ex.Message.Contains("testscope_ok"));
        }

        [Test]
        public async Task GetToken_ValidPasswordCredentials_ReturnsValidAccessToken()
        {
            var options = new AuthorizerOptions
            {
                AuthorizeEndpointUrl = new Uri("http://localhost/authorize"),
                TokenEndpointUrl = new Uri("http://localhost/token"),
                ClientId = "MyId",
                ClientSecret = "MySecret",
                Username = "MyUsername",
                Password = "MyPassword",
                GrantType = GrantType.ResourceOwnerPasswordCredentials,
                CredentialsType = credentialsType
            };

            var authorizer = new Authorizer.Authorizer(options, () => server.HttpClient);
            var result = await authorizer.GetToken();
            Assert.NotNull(result.AccessToken);
        }

        [Test]
        public void GetToken_InvalidPasswordCredentialsWithoutOnErrorCallback_ThrowsProtocolException()
        {
            var options = new AuthorizerOptions
            {
                AuthorizeEndpointUrl = new Uri("http://localhost/authorize"),
                TokenEndpointUrl = new Uri("http://localhost/token"),
                ClientId = "MyId",
                ClientSecret = "MySecret",
                Username = "MyUsername",
                Password = "WrongPassword",
                GrantType = GrantType.ResourceOwnerPasswordCredentials,
                CredentialsType = credentialsType
            };

            var authorizer = new Authorizer.Authorizer(options, () => server.HttpClient);

            var ex = Assert.Throws<ProtocolException>(async () => await authorizer.GetToken());

            Assert.IsTrue(ex.Message.Contains("invalid_grant"));
            Assert.AreEqual(HttpStatusCode.BadRequest, ex.StatusCode);
        }

        [Test]
        public async Task GetToken_InvalidPasswordCredentialsWithOnErrorCallback_OnErrorGetsCalled()
        {
            HttpStatusCode errorStatusCode = HttpStatusCode.Unused;
            string errorMessage = string.Empty;

            var options = new AuthorizerOptions
            {
                AuthorizeEndpointUrl = new Uri("http://localhost/authorize"),
                TokenEndpointUrl = new Uri("http://localhost/token"),
                ClientId = "MyId",
                ClientSecret = "MySecret",
                Username = "MyUsername",
                Password = "WrongPassword",
                GrantType = GrantType.ResourceOwnerPasswordCredentials,
                CredentialsType = credentialsType,
                OnError = (statusCode, message) =>
                {
                    errorStatusCode = statusCode;
                    errorMessage = message;
                }
            };

            var authorizer = new Authorizer.Authorizer(options, () => server.HttpClient);

            await authorizer.GetToken();

            Assert.IsTrue(errorMessage.Contains("invalid_grant"));
            Assert.AreEqual(HttpStatusCode.BadRequest, errorStatusCode);
        }

        [Test]
        public void GetToken_PasswordCredentialsWithScope_ShouldRequestScope()
        {
            var options = new AuthorizerOptions
            {
                AuthorizeEndpointUrl = new Uri("http://localhost/authorize"),
                TokenEndpointUrl = new Uri("http://localhost/token"),
                ClientId = "MyId",
                ClientSecret = "MySecret",
                Username = "MyUsername",
                Password = "MyPassword",
                GrantType = GrantType.ResourceOwnerPasswordCredentials,
                CredentialsType = credentialsType,
                Scope = new[] { "othertestscope" }
            };

            var authorizer = new Authorizer.Authorizer(options, () => server.HttpClient);
            var ex = Assert.Throws<ProtocolException>(async () => await authorizer.GetToken());
            Assert.IsTrue(ex.Message.Contains("othertestscope_ok"));
        }
    }
}
