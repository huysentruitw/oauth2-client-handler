# OAuth2 Client Handler

[![Build status](https://ci.appveyor.com/api/projects/status/9fepyg7kuhgmulh1/branch/master?svg=true)](https://ci.appveyor.com/project/huysentruitw/oauth2-client-handler/branch/master)

Managed .NET (C#) library for use with HttpClient to transparantly call authorized remote API.

## Get it on NuGet

    Install-Package OAuth2ClientHandler

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

using (var client = new HttpClient(new OAuthHttpHandler(options)))
{
    client.BaseAddress = new Uri("http://localhost");
    var response = await client.GetAsync("/api/protected_api_call");
    // ...
}
```
