using System;
using System.IO;
using System.Net.Sockets;

using System.Linq;

using Swiftness.IO;
using Swiftness.Security.Cryptography;



namespace Swiftness.Net
{
	public class SilkroadClientStream : SilkroadStream
	{
		/// <summary>
		/// Flags of the Handshake-packet
		/// </summary>
		internal enum HandshakeFlag : byte
		{
			SETUP_NONE = 0x01,
			SETUP_BLOWFISH = 0x0E,
			CHALLENGE = 0x10
		}

		/// <summary>
		/// Required variables for the handshake
		/// </summary>
		private uint dh_server_secret;
		private uint dh_client_secret;
		private uint dh_shared_secret;
		private byte[] blowfish_seed;

		/// <summary>
		/// Signal for syncing Authenticate() until the handshake is done
		/// </summary>
		private System.Threading.ManualResetEvent waitHandshake = new System.Threading.ManualResetEvent (false);

		/// <summary>
		/// Keepalive Timer for repeatetly sending 0x2002
		/// </summary>
		private System.Timers.Timer keepalive = new System.Timers.Timer (5000);


		public SilkroadClientStream (NetworkStream stream)
			: base (stream)
		{
			keepalive.Elapsed += Keepalive_Elapsed;
		}


		#region Authentication and Handshake
		protected override void HandleHandshake (Packet p)
		{
			Swiftness.IO.BinaryReader reader = new Swiftness.IO.BinaryReader (p.Payload);

			HandshakeFlag flag = (HandshakeFlag)reader.ReadByte ();

			switch (flag)
			{
				case HandshakeFlag.SETUP_BLOWFISH:
					HandshakeSetup (reader);
					break;

				case HandshakeFlag.CHALLENGE:
					HandshakeChallenge (reader);
					break;

				default:
					throw new Exception ("Unknown flag in handshake");
			}
		}

		private void HandshakeSetup (Swiftness.IO.BinaryReader reader)
		{
			/*
            Length = 0x25 => d37
            struct TPacket_5000_E {
                ushort size;
                ushort opcode;
                byte securityCount;
                byte securityCRC;
            // --------------------
                byte flag;
                byte initial_blowfish[8];
                uint seedCount;
                uint seedCRC;
                byte blowfish[8];
                uint dh_generator;
                uint dh_prime;
                uint dh_server_secret;
            }*/

			if (this.AuthenticationState != AuthenticationState.CLIENT_WAIT_SETUP)
				throw new Exception ("Unexpected flag in handshake");

			reader.ReadBytes (8);

			uint seedCount = reader.ReadUInt32 ();
			uint seedCRC = reader.ReadUInt32 ();

			blowfish_seed = reader.ReadBytes (8);

			uint dh_generator = reader.ReadUInt32 ();
			uint dh_prime = reader.ReadUInt32 ();
			dh_server_secret = reader.ReadUInt32 ();

			this.crc = new CRC ((byte)seedCRC);
			this.counter = new Counter (seedCount);

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
			dh_client_secret = G_pow_X_mod_P (
				dh_generator,
				client_random,
				dh_prime);


			// Step 4
			// Exchange the secret with the server. Since the server already send us
			// its secret, we can calculate the shared secret straigt on.
			// SECRET = G ^ X % P where X is our secret number and G is the exchanged secret
			dh_shared_secret = G_pow_X_mod_P (
				dh_server_secret,
				client_random,
				dh_prime);

			#endregion


			#region Calculate the Blowfish Key

			byte[] blowfish_key = CreateHashThing (
				dh_server_secret,
				dh_client_secret,
				dh_shared_secret,
				(byte)(dh_shared_secret & 0x03)
				);

			#endregion

			// Initialize Blowfish (temporary)
			encryptor = this.blowfish.CreateEncryptor (blowfish_key, null);
			decryptor = this.blowfish.CreateDecryptor (blowfish_key, null);

			#region Calculate Client Challenge

			byte[] client_challenge_data = CreateHashThing (
				dh_client_secret,
				dh_server_secret,
				dh_shared_secret,
				(byte)(dh_client_secret & 0x07));


			byte[] encoded_client_challenge = new byte[8];
			encryptor.TransformBlock (client_challenge_data, 0, 8, encoded_client_challenge, 0);

			#endregion

			Packet response = new Packet (0x5000);


			Swiftness.IO.BinaryWriter writer = new Swiftness.IO.BinaryWriter (response.Payload);

			writer.Write (dh_client_secret);
			writer.Write (encoded_client_challenge, 0, 8);
			writer.Flush ();

			this.AuthenticationState = AuthenticationState.CLIENT_WAIT_CHALLENGE;

			this.InnerWrite (response);
		}

		private void HandshakeChallenge (Swiftness.IO.BinaryReader reader)
		{
			/*
            struct TPacket_5000_10 {
                ushort size;
                ushort opcode;
                byte securityCount;
                byte securityCRC;
            // --------------------
                byte flag;
                byte challenge[8];
            }
            */

			if (this.AuthenticationState != AuthenticationState.CLIENT_WAIT_CHALLENGE)
				throw new Exception ("Unexpected flag in handshake");

			byte[] challenge = reader.ReadBytes (8);

			// Calculate the challenge
			byte[] server_challenge_data = CreateHashThing (
				dh_server_secret,
				dh_client_secret,
				dh_shared_secret,
				(byte)(dh_server_secret & 0x07));


			byte[] server_challenge_encoded_data = new byte[8];
			encryptor.TransformBlock (server_challenge_data, 0, 8, server_challenge_encoded_data, 0);


			if (!server_challenge_encoded_data.SequenceEqual<byte> (challenge))
			{
				throw new Exception ("Invalid Challenge in Handshake");
			}

			// Calculate the final blowfish key

			byte[] final_blowfishkey = new byte[8];

			// Copy the basekey into the array
			Array.ConstrainedCopy (blowfish_seed, 0, final_blowfishkey, 0, 8);

			// Magic function that mixes everything together
			KeyTransformValue (
				ref final_blowfishkey,
				dh_shared_secret,
				(byte)0x03);

			// Initialize Blowfish (final)
			encryptor = this.blowfish.CreateEncryptor (final_blowfishkey, null);
			decryptor = this.blowfish.CreateDecryptor (final_blowfishkey, null);

			// Send 0x9000 - HANDSHAKE ACCEPT
			this.InnerWrite (new Packet (0x9000, false, new byte[0]));

			this.AuthenticationState = AuthenticationState.DONE;

			waitHandshake.Set ();
		}

		public override void Authenticate ()
		{
			this.AuthenticationState = AuthenticationState.CLIENT_WAIT_SETUP;
			this.BeginReadLength ();

			waitHandshake.WaitOne ();

			keepalive.Start ();

		}

		internal byte[] CreateHashThing (uint part1, uint part2, uint shared_secret, byte keyByte)
		{
			byte[] data = new byte[8];

			Array.ConstrainedCopy (BitConverter.GetBytes (part1), 0, data, 0, 4);
			Array.ConstrainedCopy (BitConverter.GetBytes (part2), 0, data, 4, 4);

			KeyTransformValue (ref data, shared_secret, keyByte);

			return data;
		}
		#endregion


		#region Session Keep-alive
		/// <summary>
		/// Gets or sets the keepalive-interval in milliseconds (default 5000)
		/// </summary>
		/// <remarks>This is simply a wrapper around System.Timers.Timer</remarks>
		public double KeepaliveInterval
		{
			get
			{
				return keepalive.Interval;
			}
			set
			{
				keepalive.Interval = value;
			}
		}

		/// <summary>
		/// Callback executed when the timeout elapses
		/// </summary>
		/// <param name="sender"></param>
		/// <param name="e"></param>
		private void Keepalive_Elapsed (object sender, System.Timers.ElapsedEventArgs e)
		{
			this.Write (new Packet (0x2002));
		}

		#endregion



	}
}