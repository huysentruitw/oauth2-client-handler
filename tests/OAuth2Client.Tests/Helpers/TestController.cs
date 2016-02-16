using System.Web.Http;

namespace OAuth2Client.Tests.Helpers
{
    [RoutePrefix("api")]
    public class TestController : ApiController
    {
        [Route("authorize"), Authorize, HttpGet]
        public IHttpActionResult Authorized()
        {
            return Ok();
        }

        [Route("unauthorized"), Authorize(Roles = "admin"), HttpGet]
        public IHttpActionResult Unauthorized()
        {
            return Ok();
        }
    }
}
