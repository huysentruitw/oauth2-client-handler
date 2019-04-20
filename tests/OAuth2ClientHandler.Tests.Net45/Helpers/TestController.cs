using System.Web.Http;

namespace OAuth2ClientHandler.Tests
{
    [RoutePrefix("api")]
    public class TestController : ApiController
    {
        [Route("authorize"), Authorize, HttpGet]
        public IHttpActionResult AuthorizedAction()
        {
            return Ok();
        }

        [Route("unauthorized"), Authorize(Roles = "admin"), HttpGet]
        public IHttpActionResult UnauthorizedAction()
        {
            return Ok();
        }
    }
}
