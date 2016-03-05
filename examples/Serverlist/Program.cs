using System;

using System.Net.Sockets;
using Swiftness.Net;

namespace Serverlist
{
    class Program
    {
        static void Main(string[] args)
        {
            TcpClient client = new TcpClient ();


            client.Connect("5.39.47.168", 15779);
			//client.Connect ("5.189.130.227", 15779);
			
			SilkroadClientStream stream = new SilkroadClientStream (client.GetStream ());
			stream.Authenticate ();

            Console.Read();
			
        }
    }
}
