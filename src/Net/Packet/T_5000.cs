using System;
using System.IO;
using System.Net.Sockets;

namespace Swiftness.Net
{
	internal enum HandshakeFlag : byte
	{
		NONE = 0x01,
		BLOWFISH_HANDSHAKE = 0x0E,
		BLOWFISH_CHALLENGE = 0x10
	}
	
	internal class T_5000
	{
		public HandshakeFlag flag;
		
		/// <summary>
		/// Tries to parse the given data into a substruct of 0x5000
		/// </summary>
		public static T_5000 TryParse (System.IO.MemoryStream stream)
		{
			return TryParse (new BinaryReader (stream));
		}
		
		/// <summary>
		/// Tries to parse the given data into a substruct of 0x5000
		/// </summary>
		public static T_5000 TryParse (BinaryReader reader)
		{
			// The flag is part of all handshake (0x5000) packets and determines the mode
			HandshakeFlag t_flag = (HandshakeFlag)reader.ReadByte ();
			
			switch (t_flag) {
			case HandshakeFlag.BLOWFISH_HANDSHAKE:
				return new T_5000_E (reader) { flag = t_flag };
				
			case HandshakeFlag.BLOWFISH_CHALLENGE:
				return new T_5000_10 (reader) { flag = t_flag };
				
			default:
				throw new System.IO.InvalidDataException (string.Format (
						"Invalid Mode in authentication ({0:X4})", (byte)t_flag)
				);
			}
				
		}
	}
	
	internal class T_5000_E : T_5000
	{
		
		public byte[] inital;
		public int seedCount;
		public int seedCRC;
		public byte[] blowfish;
		public uint dh_generator;
		public uint dh_prime;
		public uint dh_server_secret;

		public T_5000_E (BinaryReader reader)
		{
			inital = reader.ReadBytes (8);
			seedCount = reader.ReadInt32 ();
			seedCRC = reader.ReadInt32 ();
			blowfish = reader.ReadBytes (8);
			dh_generator = reader.ReadUInt32 ();
			dh_prime = reader.ReadUInt32 ();
			dh_server_secret = reader.ReadUInt32 ();
		}
	}
	
	internal class T_5000_10 : T_5000 {
		public byte[] challenge;
		
		public T_5000_10 (BinaryReader reader)
		{
			challenge = reader.ReadBytes (8);
		}
			
	}

}

