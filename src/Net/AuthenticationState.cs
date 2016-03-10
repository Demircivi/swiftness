using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Swiftness.Net
{
    public enum AuthenticationState
    {
        NONE,
        CLIENT_WAIT_SETUP,        // Client is waiting for the inital setup packet
        SERVER_WAIT_CHALLENGE,    // The Server has send the setup and is waiting for the challenge of the client
        CLIENT_WAIT_CHALLENGE,    // The client has sent its challenge and is waiting for the server challenge
        DONE                      // The handshake is done 
    }
}
