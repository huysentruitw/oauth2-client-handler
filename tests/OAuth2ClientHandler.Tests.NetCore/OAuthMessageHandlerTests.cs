using System;
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
    public class OAuthMessageHandlerTests
    {
        private TestServer _server;
        private HttpMessageHandler _handler;

        [SetUp]
        public void SetUp()
        {
            _server = TestServerBuilder.Build();
            _handler = _server.CreateHandler();
        }

        [TearDown]
        public void TearDown()
        {
            _server.Dispose();
        }

        [Test]
        public async Task OAuthHttpHandler_ValidClientCredentials_ShouldReturnOk()
        {
            var options = new OAuthHttpHandlerOptions
            {
                AuthorizerOptions = new AuthorizerOptions
                {
                    AuthorizeEndpointUrl = new Uri(_server.BaseAddress, "/connect/authorize"),
                    TokenEndpointUrl = new Uri(_server.BaseAddress, "/connect/token"),
                    ClientId = "MyId",
                    ClientSecret = "MySecret",
                    GrantType = GrantType.ClientCredentials,
                    Scope = new[] { "test" }
                },
                InnerHandler = _handler
            };

            using (var client = new HttpClient(new OAuthHttpHandler(options)))
            {
                client.BaseAddress = _server.BaseAddress;
                var response = await client.GetAsync("/api/authorize");
                Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            }
        }

        [Test]
        public void OAuthHttpHandler_InvalidClientCredentialsWithoutOnErrorCallback_ShouldThrowProtocolException()
        {
            var options = new OAuthHttpHandlerOptions
            {
                AuthorizerOptions = new AuthorizerOptions
                {
                    AuthorizeEndpointUrl = new Uri(_server.BaseAddress, "/connect/authorize"),
                    TokenEndpointUrl = new Uri(_server.BaseAddress, "/connect/token"),
                    ClientId = "WrongId",
                    ClientSecret = "WrongSecret",
                    GrantType = GrantType.ClientCredentials
                },
                InnerHandler = _handler
            };

            using (var client = new HttpClient(new OAuthHttpHandler(options)))
            {
                client.BaseAddress = _server.BaseAddress;
                var ex = Assert.ThrowsAsync<ProtocolException>(async () => await client.GetAsync("/api/authorize"));
                Assert.AreEqual(HttpStatusCode.BadRequest, ex.StatusCode);
            }
        }

        [Test]
        public async Task OAuthHttpHandler_InvalidClientCredentialsWithOnErrorCallback_ShouldReturnUnauthorized()
        {
            var options = new OAuthHttpHandlerOptions
            {
                AuthorizerOptions = new AuthorizerOptions
                {
                    AuthorizeEndpointUrl = new Uri(_server.BaseAddress, "/connect/authorize"),
                    TokenEndpointUrl = new Uri(_server.BaseAddress, "/connect/token"),
                    ClientId = "WrongId",
                    ClientSecret = "WrongSecret",
                    GrantType = GrantType.ClientCredentials,
                    OnError = (statusCode, message) => { }
                },
                InnerHandler = _handler
            };

            using (var client = new HttpClient(new OAuthHttpHandler(options)))
            {
                client.BaseAddress = _server.BaseAddress;
                var response = await client.GetAsync("/api/authorize");
                Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);
            }
        }

        [Test]
        public async Task OAuthHttpHandler_InvalidRequestUri_ShouldReturnNotFound()
        {
            var options = new OAuthHttpHandlerOptions
            {
                AuthorizerOptions = new AuthorizerOptions
                {
                    AuthorizeEndpointUrl = new Uri(_server.BaseAddress, "/connect/authorize"),
                    TokenEndpointUrl = new Uri(_server.BaseAddress, "/connect/token"),
                    ClientId = "MyId",
                    ClientSecret = "MySecret",
                    GrantType = GrantType.ClientCredentials
                },
                InnerHandler = _handler
            };

            using (var client = new HttpClient(new OAuthHttpHandler(options)))
            {
                client.BaseAddress = _server.BaseAddress;
                var response = await client.GetAsync("/api/invalid");
                Assert.AreEqual(HttpStatusCode.NotFound, response.StatusCode);
            }
        }

        [Test]
        public async Task OAuthHttpHandler_UnauthorizedRequest_ShouldReturnForbidden()
        {
            var options = new OAuthHttpHandlerOptions
            {
                AuthorizerOptions = new AuthorizerOptions
                {
                    AuthorizeEndpointUrl = new Uri(_server.BaseAddress, "/connect/authorize"),
                    TokenEndpointUrl = new Uri(_server.BaseAddress, "/connect/token"),
                    ClientId = "MyId",
                    ClientSecret = "MySecret",
                    GrantType = GrantType.ClientCredentials
                },
                InnerHandler = _handler
            };

            using (var client = new HttpClient(new OAuthHttpHandler(options)))
            {
                client.BaseAddress = _server.BaseAddress;
                var response = await client.GetAsync("/api/unauthorized");
                Assert.AreEqual(HttpStatusCode.Forbidden, response.StatusCode);
            }
        }
    }
}
