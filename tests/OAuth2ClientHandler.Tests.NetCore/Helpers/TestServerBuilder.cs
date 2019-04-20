using System;
using System.Linq;
using IdentityServer4.Models;
using IdentityServer4.Test;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace OAuth2ClientHandler.Tests.NetCore.Helpers
{
    internal sealed class TestServerBuilder
    {
        public static TestServer Build()
        {
            TestServer testServer = null;
            testServer = new TestServer(new WebHostBuilder()
                .ConfigureServices(services =>
                {
                    services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_2);

                    services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                        .AddJwtBearer(options =>
                        {
                            options.BackchannelHttpHandler = testServer?.CreateHandler();
                            options.MetadataAddress = "https://localhost/.well-known/openid-configuration";
                            options.TokenValidationParameters.ValidateAudience = false;
                        });

                    services.AddIdentityServer()
                        .AddDeveloperSigningCredential()
                        .AddTestUsers(new[]
                        {
                            new TestUser { SubjectId = "MySubjectId", Username = "MyUsername", Password = "MyPassword" }
                        }.ToList())
                        .AddInMemoryClients(new[]
                        {
                            new Client
                            {
                                ClientId = "MyId",
                                ClientSecrets = new[] { new Secret("MySecret".Sha256()) },
                                Enabled = true,
                                AllowedGrantTypes = GrantTypes.ResourceOwnerPasswordAndClientCredentials,
                                AllowedScopes = new[] { "test" }
                            }
                        })
                        .AddInMemoryApiResources(new ApiResource[]
                        {
                            new ApiResource
                            {
                                Enabled = true,
                                Scopes = new[] { new Scope("test") }
                            }
                        });
                })
                .Configure(app =>
                {
                    app.UseAuthentication();
                    app.UseIdentityServer();
                    app.UseMvc();
                }))
            {
                BaseAddress = new Uri("https://localhost")
            };

            return testServer;
        }
    }
}
