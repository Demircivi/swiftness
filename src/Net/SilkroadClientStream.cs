using System;
using System.Net.Sockets;

using System.Linq;

using Swiftness.IO;
using Swiftness.Security.Cryptography;



namespace Swiftness.Net
{
	public class SilkroadClientStream : SilkroadStream
	{
		public SilkroadClientStream (NetworkStream stream)
			: base(stream)
		{
		}
		
		public override void Authenticate ()
		{
			#region Init
			
			Packet p_setup = this.Read ();
			
			if (p_setup.OpCode != 0x5000) {
				throw new Exception (string.Format ("Invalid Opcode in authentication ({0:X4})", p_setup.OpCode));
			}
			
			T_5000 payload = T_5000.TryParse (p_setup.Payload);
			
			if (payload.flag != HandshakeFlag.BLOWFISH_HANDSHAKE) {
				throw new Exception ();
			}
			
			uint dh_server_secret = ((T_5000_E)payload).dh_server_secret;
			
			// Initialize CRC
			this.crc = new Swiftness.Security.Cryptography.CRC ((byte)((T_5000_E)payload).seedCRC);
			
			// Initialize Counter
			this.counter = new Counter ((uint)((T_5000_E)payload).seedCount);
			
			
			#region Diffie Hellmann Keyexchange
			// Step 1
			// Server and Client should agree on a modulus P and a base G
			// In Silkroad, these are predefined by the server.
			// For now, we trust the server. Checking the numbers to be correct
			// could be considered but is not really necessary as the keyexchange is
			// bruteforce-able anyways.
			
			// Step 2
			// Calculate a random secret number.
			
			// 0x33 was set by the 0x33.org-community to enable others to 
			// analyze packets without having to find the client random.
			uint client_random = 0x33;
			
			// Step 3
			// Calculate the exchangable secret number, where X is our secret number.
			// A = G ^ X % P
			uint dh_client_secret = G_pow_X_mod_P (
				((T_5000_E)payload).dh_generator,
				client_random, 
				((T_5000_E)payload).dh_prime);
			
			// Step 4
			// Exchange the secret with the server. Since the server already send us
			// its secret, we can calculate the shared secret straigt on.
			// SECRET = G ^ X % P where X is our secret number and G is the exchanged secret
			uint dh_shared_secret = G_pow_X_mod_P (
				dh_server_secret,
                client_random, 
				((T_5000_E)payload).dh_prime);
			
			#endregion
			
			#region Calculate the Blowfish Key
			
			
			byte[] blowfish_key = CreateHashThing (
				dh_server_secret,
                dh_client_secret,
				dh_shared_secret,
				(byte)(dh_shared_secret & 0x03)
				);
			
			#endregion
			
			// Initialize Blowfish
			encryptor = blowfish.CreateEncryptor (blowfish_key, null);
			decryptor = blowfish.CreateDecryptor (blowfish_key, null);
			
			#region Client Challenge to Server
			
			// Encode Challenge to Server
			byte[] client_challenge_data = CreateHashThing (
				dh_client_secret,
				dh_server_secret,
				dh_shared_secret,
				(byte)(dh_client_secret & 0x07));
			
			byte[] encoded_data = new byte[8];
			encryptor.TransformBlock (client_challenge_data, 0, 8, encoded_data, 0);
			
			// Build the Packet
			// [Client Secret][Blowfish Data]
			
			Packet response = new Packet () {
				Encrypted = false,
				OpCode = 0x5000,
				Payload = new System.IO.MemoryStream()
			};
			
			BinaryWriter writer = new BinaryWriter (response.Payload);
			writer.Write (dh_client_secret);
			writer.Write (encoded_data, 0, 8);
			writer.Flush ();
			
			this.Write (response);
			
			#endregion
			
			#endregion
			
			#region Challenge
			
			Packet p_challenge = this.Read ();
			
			
			if (p_challenge.OpCode != 0x5000) {
				throw new Exception (string.Format ("Invalid Opcode in authentication ({0:X4})", p_setup.OpCode));
			}
			
			T_5000 payload_challenge = T_5000.TryParse (p_challenge.Payload);
			
			if (payload_challenge.flag != HandshakeFlag.BLOWFISH_CHALLENGE) {
				throw new Exception ();
			}
			
			#region Calculate Challenge
			
            byte[] server_challenge_data = CreateHashThing(dh_server_secret, dh_client_secret, dh_shared_secret, (byte)(dh_server_secret & 0x07));


            byte[] server_challenge_encoded_data = new byte[8];
            encryptor.TransformBlock(server_challenge_data, 0, 8, server_challenge_encoded_data, 0);

            if ( ! server_challenge_encoded_data.SequenceEqual<byte>(((T_5000_10)payload_challenge).challenge) )
            {
                throw new Exception("Invalid Challenge in Handshake");
            }
			
			#endregion
			
			
			#endregion
        }
		
		internal byte[] CreateHashThing (uint part1, uint part2, uint shared_secret, byte keyByte)
		{
			byte[] data = new byte[8];
			
			Array.ConstrainedCopy (BitConverter.GetBytes (part1), 0, data, 0, 4);
			Array.ConstrainedCopy (BitConverter.GetBytes (part2), 0, data, 4, 4);
			
			KeyTransformValue (ref data, shared_secret, keyByte);
			
			return data;
		}
		
		
	}
}