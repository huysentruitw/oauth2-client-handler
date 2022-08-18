# OAuth2 Client Handler

[![Build status](https://ci.appveyor.com/api/projects/status/9fepyg7kuhgmulh1/branch/master?svg=true)](https://ci.appveyor.com/project/huysentruitw/oauth2-client-handler/branch/master)

Managed .NET library for use with HttpClient to transparantly call authorized remote API protected with OAuth2 or OpenID Connect.

Supports .NET Framework 4.5+ and .NET Standard / .NET Core.

## Get it on NuGet

    PM> Install-Package OAuth2ClientHandler

## Usage

```C#
var options = new OAuthHttpHandlerOptions
{
    AuthorizerOptions = new AuthorizerOptions
    {
        AuthorizeEndpointUrl = new Uri("http://localhost/authorizer"),
        TokenEndpointUrl = new Uri("http://localhost/token"),
        ClientId = "MyId",
        ClientSecret = "MySecret",
        GrantType = GrantType.ClientCredentials
    }
};

var oAuthHttpHandler = new OAuthHttpHandler(options)
{
    InnerHandler = new HttpClientHandler()
};

using (var client = new HttpClient(oAuthHttpHandler))
{
    client.BaseAddress = new Uri("http://localhost");
    var response = await client.GetAsync("/api/protected_api_call");
    // ...
}
```
