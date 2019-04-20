using System;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.TestHost;
using NUnit.Framework;
using OAuth2ClientHandler.Authorizer;
using OAuth2ClientHandler.Tests.NetCore.Helpers;

namespace OAuth2ClientHandler.Tests.NetCore
{
    [TestFixture]
    public class AuthorizerTests
    {
        private TestServer _server;
        private HttpClient _httpClient;

        [SetUp]
        public void SetUp()
        {
            _server = TestServerBuilder.Build();
            _httpClient = _server.CreateClient();
        }

        [TearDown]
        public void TearDown()
        {
            _server.Dispose();
        }

        [Test]
        public async Task GetToken_ValidClientCredentials_ReturnsValidAccessToken()
        {
            var options = new AuthorizerOptions
            {
                AuthorizeEndpointUrl = new Uri(_server.BaseAddress, "/connect/authorize"),
                TokenEndpointUrl = new Uri(_server.BaseAddress, "/connect/token"),
                ClientId = "MyId",
                ClientSecret = "MySecret",
                GrantType = GrantType.ClientCredentials
            };

            var authorizer = new Authorizer.Authorizer(options, () => _httpClient);
            var result = await authorizer.GetToken();
            Assert.NotNull(result.AccessToken);
        }

        [Test]
        public async Task GetToken_ValidClientCredentials_FormsAuthentication_ReturnsValidAccessToken()
        {
            var options = new AuthorizerOptions
            {
                AuthorizeEndpointUrl = new Uri(_server.BaseAddress, "/connect/authorize"),
                TokenEndpointUrl = new Uri(_server.BaseAddress, "/connect/token"),
                ClientId = "MyId",
                ClientSecret = "MySecret",
                GrantType = GrantType.ClientCredentials,
                CredentialTransportMethod = CredentialTransportMethod.FormAuthenticationCredentials
            };

            var authorizer = new Authorizer.Authorizer(options, () => _httpClient);
            var result = await authorizer.GetToken();
            Assert.NotNull(result.AccessToken);
        }

        [Test]
        public void GetToken_InvalidClientCredentialsWithoutOnErrorCallback_ThrowsProtocolException()
        {
            var options = new AuthorizerOptions
            {
                AuthorizeEndpointUrl = new Uri(_server.BaseAddress, "/connect/authorize"),
                TokenEndpointUrl = new Uri(_server.BaseAddress, "/connect/token"),
                ClientId = "WrongId",
                ClientSecret = "WrongSecret",
                GrantType = GrantType.ClientCredentials
            };

            var authorizer = new Authorizer.Authorizer(options, () => _httpClient);
            
            var ex = Assert.ThrowsAsync<ProtocolException>(async () => await authorizer.GetToken());
            
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
                AuthorizeEndpointUrl = new Uri(_server.BaseAddress, "/connect/authorize"),
                TokenEndpointUrl = new Uri(_server.BaseAddress, "/connect/token"),
                ClientId = "WrongId",
                ClientSecret = "WrongSecret",
                GrantType = GrantType.ClientCredentials,
                OnError = (statusCode, message) =>
                {
                    errorStatusCode = statusCode;
                    errorMessage = message;
                }
            };

            var authorizer = new Authorizer.Authorizer(options, () => _httpClient);

            await authorizer.GetToken();

            Assert.IsTrue(errorMessage.Contains("invalid_client"));
            Assert.AreEqual(HttpStatusCode.BadRequest, errorStatusCode);
        }

        [Test]
        public void GetToken_InvalidTokenEndpointUrl_ThrowsProtocolException()
        {
            var options = new AuthorizerOptions
            {
                AuthorizeEndpointUrl = new Uri(_server.BaseAddress, "/connect/authorize"),
                TokenEndpointUrl = new Uri(_server.BaseAddress, "/connect/tokenbla"),
                ClientId = "MyId",
                ClientSecret = "MySecret",
                GrantType = GrantType.ClientCredentials
            };

            var authorizer = new Authorizer.Authorizer(options, () => _httpClient);
            var ex = Assert.ThrowsAsync<ProtocolException>(async () => await authorizer.GetToken());
            Assert.AreEqual(HttpStatusCode.NotFound, ex.StatusCode);
        }

        [Test]
        public async Task GetToken_ClientCredentialsWithScope_ShouldRequestScope()
        {
            var options = new AuthorizerOptions
            {
                AuthorizeEndpointUrl = new Uri(_server.BaseAddress, "/connect/authorize"),
                TokenEndpointUrl = new Uri(_server.BaseAddress, "/connect/token"),
                ClientId = "MyId",
                ClientSecret = "MySecret",
                GrantType = GrantType.ClientCredentials,
                Scope = new[] { "test" }
            };

            var authorizer = new Authorizer.Authorizer(options, () => _httpClient);
            var token = new JwtSecurityToken((await authorizer.GetToken()).AccessToken);
            var scope = token.Claims.FirstOrDefault(x => x.Type == "scope");
            Assert.That(scope, Is.Not.Null);
            Assert.That(scope.Value, Is.EqualTo("test"));
        }

        [Test]
        public async Task GetToken_ValidPasswordCredentials_ReturnsValidAccessToken()
        {
            var options = new AuthorizerOptions
            {
                AuthorizeEndpointUrl = new Uri(_server.BaseAddress, "/connect/authorize"),
                TokenEndpointUrl = new Uri(_server.BaseAddress, "/connect/token"),
                ClientId = "MyId",
                ClientSecret = "MySecret",
                Username = "MyUsername",
                Password = "MyPassword",
                GrantType = GrantType.ResourceOwnerPasswordCredentials
            };

            var authorizer = new Authorizer.Authorizer(options, () => _httpClient);
            var result = await authorizer.GetToken();
            Assert.NotNull(result.AccessToken);
        }

        [Test]
        public void GetToken_InvalidPasswordCredentialsWithoutOnErrorCallback_ThrowsProtocolException()
        {
            var options = new AuthorizerOptions
            {
                AuthorizeEndpointUrl = new Uri(_server.BaseAddress, "/connect/authorize"),
                TokenEndpointUrl = new Uri(_server.BaseAddress, "/connect/token"),
                ClientId = "MyId",
                ClientSecret = "MySecret",
                Username = "MyUsername",
                Password = "WrongPassword",
                GrantType = GrantType.ResourceOwnerPasswordCredentials
            };

            var authorizer = new Authorizer.Authorizer(options, () => _httpClient);

            var ex = Assert.ThrowsAsync<ProtocolException>(async () => await authorizer.GetToken());

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
                AuthorizeEndpointUrl = new Uri(_server.BaseAddress, "/connect/authorize"),
                TokenEndpointUrl = new Uri(_server.BaseAddress, "/connect/token"),
                ClientId = "MyId",
                ClientSecret = "MySecret",
                Username = "MyUsername",
                Password = "WrongPassword",
                GrantType = GrantType.ResourceOwnerPasswordCredentials,
                OnError = (statusCode, message) =>
                {
                    errorStatusCode = statusCode;
                    errorMessage = message;
                }
            };

            var authorizer = new Authorizer.Authorizer(options, () => _httpClient);

            await authorizer.GetToken();

            Assert.IsTrue(errorMessage.Contains("invalid_grant"));
            Assert.AreEqual(HttpStatusCode.BadRequest, errorStatusCode);
        }

        [Test]
        public async Task GetToken_PasswordCredentialsWithScope_ShouldRequestScope()
        {
            var options = new AuthorizerOptions
            {
                AuthorizeEndpointUrl = new Uri(_server.BaseAddress, "/connect/authorize"),
                TokenEndpointUrl = new Uri(_server.BaseAddress, "/connect/token"),
                ClientId = "MyId",
                ClientSecret = "MySecret",
                Username = "MyUsername",
                Password = "MyPassword",
                GrantType = GrantType.ResourceOwnerPasswordCredentials,
                Scope = new[] { "test" }
            };

            var authorizer = new Authorizer.Authorizer(options, () => _httpClient);
            var token = new JwtSecurityToken((await authorizer.GetToken()).AccessToken);
            var scope = token.Claims.FirstOrDefault(x => x.Type == "scope");
            Assert.That(scope, Is.Not.Null);
            Assert.That(scope.Value, Is.EqualTo("test"));
        }
    }
}
