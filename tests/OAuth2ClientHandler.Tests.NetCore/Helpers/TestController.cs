using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace OAuth2ClientHandler.Tests
{
    [Route("api")]
    [ApiController]
    public class TestController : ControllerBase
    {
        [HttpGet]
        [Route("authorize")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public IActionResult AuthorizedAction()
        {
            return Ok();
        }

        [HttpGet]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme, Roles = "admin")]
        [Route("unauthorized")]
        public IActionResult UnauthorizedAction()
        {
            return Ok();
        }
    }
}
