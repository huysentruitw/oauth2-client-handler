using System;
using System.Net;

namespace OAuth2ClientHandler
{
    public sealed class ProtocolException : Exception
    {
        public ProtocolException(HttpStatusCode statusCode, string message)
            : base(message)
        {
            StatusCode = statusCode;
        }

        public HttpStatusCode StatusCode { get; private set; }
    }
}
