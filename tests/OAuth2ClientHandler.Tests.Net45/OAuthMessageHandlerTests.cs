using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Owin.Testing;
using NUnit.Framework;
using OAuth2ClientHandler.Authorizer;

namespace OAuth2ClientHandler.Tests.Net45
{
    [TestFixture]
    public class OAuthMessageHandlerTests
    {
        private TestServer _server;

        [SetUp]
        public void SetUp()
        {
            _server = TestServer.Create<Startup>();
        }

        [TearDown]
        public void TearDown()
        {
            _server.Dispose();
        }

        private HttpMessageHandler Handler => _server.Handler;

        [Test]
        public async Task OAuthHttpHandler_ValidClientCredentials_ShouldReturnOk()
        {
            var options = new OAuthHttpHandlerOptions
            {
                AuthorizerOptions = new AuthorizerOptions
                {
                    AuthorizeEndpointUrl = new Uri("http://localhost/authorizer"),
                    TokenEndpointUrl = new Uri("http://localhost/token"),
                    ClientId = "MyId",
                    ClientSecret = "MySecret",
                    GrantType = GrantType.ClientCredentials
                },
                InnerHandler = Handler
            };

            using (var client = new HttpClient(new OAuthHttpHandler(options)))
            {
                client.BaseAddress = new Uri("http://localhost");
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
                    AuthorizeEndpointUrl = new Uri("http://localhost/authorizer"),
                    TokenEndpointUrl = new Uri("http://localhost/token"),
                    ClientId = "WrongId",
                    ClientSecret = "WrongSecret",
                    GrantType = GrantType.ClientCredentials
                },
                InnerHandler = Handler
            };

            using (var client = new HttpClient(new OAuthHttpHandler(options)))
            {
                client.BaseAddress = new Uri("http://localhost");
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
                    AuthorizeEndpointUrl = new Uri("http://localhost/authorizer"),
                    TokenEndpointUrl = new Uri("http://localhost/token"),
                    ClientId = "WrongId",
                    ClientSecret = "WrongSecret",
                    GrantType = GrantType.ClientCredentials,
                    OnError = (statusCode, message) => { }
                },
                InnerHandler = Handler
            };

            using (var client = new HttpClient(new OAuthHttpHandler(options)))
            {
                client.BaseAddress = new Uri("http://localhost");
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
                    AuthorizeEndpointUrl = new Uri("http://localhost/authorizer"),
                    TokenEndpointUrl = new Uri("http://localhost/token"),
                    ClientId = "MyId",
                    ClientSecret = "MySecret",
                    GrantType = GrantType.ClientCredentials
                },
                InnerHandler = Handler
            };

            using (var client = new HttpClient(new OAuthHttpHandler(options)))
            {
                client.BaseAddress = new Uri("http://localhost");
                var response = await client.GetAsync("/api/invalid");
                Assert.AreEqual(HttpStatusCode.NotFound, response.StatusCode);
            }
        }

        [Test]
        public async Task OAuthHttpHandler_UnauthorizedRequest_ShouldReturnUnauthorized()
        {
            var options = new OAuthHttpHandlerOptions
            {
                AuthorizerOptions = new AuthorizerOptions
                {
                    AuthorizeEndpointUrl = new Uri("http://localhost/authorizer"),
                    TokenEndpointUrl = new Uri("http://localhost/token"),
                    ClientId = "MyId",
                    ClientSecret = "MySecret",
                    GrantType = GrantType.ClientCredentials
                },
                InnerHandler = Handler
            };

            using (var client = new HttpClient(new OAuthHttpHandler(options)))
            {
                client.BaseAddress = new Uri("http://localhost");
                var response = await client.GetAsync("/api/unauthorized");
                Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);
            }
        }
    }
}
