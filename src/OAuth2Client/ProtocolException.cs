using System;
using System.Net;

namespace OAuth2Client
{
    public class ProtocolException : Exception
    {
        public ProtocolException(HttpStatusCode statusCode, string message)
            : base(message)
        {
            this.StatusCode = statusCode;
        }

        public HttpStatusCode StatusCode { get; private set; }
    }
}
