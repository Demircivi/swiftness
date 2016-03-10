using System;

namespace Swiftness.Net
{
    class AuthenticationException : Exception
    {
        public AuthenticationException() 
            : base()
        {

        }

        public AuthenticationException(string message) 
            : base(message)
        {

        }
    }
}
