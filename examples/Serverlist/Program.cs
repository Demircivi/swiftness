using System;

using System.Net.Sockets;
using Swiftness.Net;

namespace Serverlist
{
	class Program
	{
		static void Main (string[] args)
		{
			TcpClient client = new TcpClient ();
			
			//client.Connect ("121.128.133.53", 15779);
			//client.Connect ("5.189.130.227", 15779);
			client.Connect ("5.39.47.168", 15779);

			SilkroadClientStream stream = new SilkroadClientStream (client.GetStream ());

			stream.Authenticate ();


			Packet ident = new Packet (0x2001);

			Swiftness.IO.BinaryWriter writer = new Swiftness.IO.BinaryWriter (ident.Payload);

			writer.Write ("SR_Client", true);
			writer.Write ((byte)0);

			stream.Write (ident);

			Packet serverident = stream.Read ();

			Swiftness.IO.BinaryReader reader = new Swiftness.IO.BinaryReader (serverident.Payload);

			string name = reader.ReadString (true);

			Console.WriteLine ("Connected to: {0}", name);


			Packet version_info = new Packet (0x6101);

			stream.Write (version_info);


			while (true)
			{
				Packet something = stream.Read ();

				if (something.MsgId == 0xA101)
				{
					Swiftness.IO.BinaryReader list_reader = new Swiftness.IO.BinaryReader (something.Payload);

					//System.IO.File.WriteAllBytes ("packet.bin", something.Payload.ToArray ());

					while (list_reader.ReadByte () == 1)
					{
						byte realmId = list_reader.ReadByte ();

						string realm_name = list_reader.ReadString (true);

						Console.WriteLine ("Realm: 0x{0,2:x} - {1}", realmId, realm_name);
					}

					
					while (list_reader.ReadByte () == 1)
					{
						ushort id = list_reader.ReadUInt16 ();

						string server_name = list_reader.ReadString (true);

						ushort curPlayers = list_reader.ReadUInt16 ();
						ushort maxPlayers = list_reader.ReadUInt16 ();
						byte state = list_reader.ReadByte ();

						Console.WriteLine ("{0,4} | {1,15} {2,4}/{3,4} 0x{4:x2}", id, server_name, curPlayers, maxPlayers, state);
					}
				}
			}


			Console.Read ();
		}
	}
}
