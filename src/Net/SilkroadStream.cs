using System;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;


using Swiftness.Security.Cryptography;

namespace Swiftness.Net
{
	/// <summary>
	/// Generic stream implementing the silkroad protocol.
	/// </summary>
	/// <remarks>
	/// This class is abstract because it can not be instanciated directly.
	/// Use SilkroadClientStream or SilkroadServerStream instead.
	/// </remarks>
	public abstract class SilkroadStream : PacketStream
	{
		protected CRC crc;
		protected Blowfish blowfish;
		protected ICryptoTransform encryptor;
		protected ICryptoTransform decryptor;
		internal Counter counter;
		
		
		public SilkroadStream (NetworkStream stream) 
			: base(stream)
		{
			blowfish = Blowfish.Create ();
		}
		
		public abstract void Authenticate();
		
		public override Packet Read ()
		{
			BinaryReader reader = new BinaryReader (this.InnerStream);
			
			short len = reader.ReadInt16 ();
			short opcode = reader.ReadInt16 ();
			
			byte sec_count = reader.ReadByte ();
			byte sec_crc = reader.ReadByte ();
			
			byte[] data = reader.ReadBytes (len);
			
			Console.WriteLine (
				"[PacketStream] S->C [{0:X4}][{1:X4}][{2:X2}][{3:X2}]", 
				len, 
				opcode, 
				sec_crc, 
				sec_count);
			
			return new Packet () {
				OpCode = opcode,
				CRC = sec_crc,
				SecurityCount = sec_count,
				Payload = new MemoryStream(data)
			};
		}
		
		public override void Write (Packet packet)
		{
			lock (this) {
				// Calculate Security Count
				byte count = this.counter.GenerateCountByte ();
				
				// Build Byte[] from Packet
				MemoryStream ms = new MemoryStream ();
				BinaryWriter writer = new BinaryWriter (ms);
				
				ushort len = (ushort)packet.Payload.Length;
				
				// Set encrypted-flag if packet is encrypted
				if (packet.Encrypted)
					len |= 0x8000;
				
				
				// [2 len][2 op][count][crc]
				writer.Write (len);
				writer.Write (packet.OpCode);
				writer.Write (count);
				writer.Write ((byte)0);
				writer.Flush ();
				
				packet.Payload.WriteTo (ms);
				
				
				// Calculate CRC
				byte checksum = this.crc.Calculate (ms.ToArray ());
				
				writer.Seek (5, SeekOrigin.Begin);
				writer.Write (checksum);
				
							
				Console.WriteLine (
				"[PacketStream] C->S [{0:X4}][{1:X4}][{2:X2}][{3:X2}]", 
				len, 
				packet.OpCode, 
				checksum, 
				count);
			
				
				// Write Packet to Stream
				this.InnerStream.Write (ms.ToArray (), 0, (int)ms.Length);
			}
		}
		
		public override void Flush ()
		{
			throw new System.NotImplementedException ();
		}
		
		
		
		/// <summary>
		/// Fast way to calculate G^X % P without overflowing datatypes
		/// </summary>
		/// <remarks>
		/// This function was written by jMerlin as part of the article "How to generate the security bytes for SRO".
		/// </remarks>
		protected uint G_pow_X_mod_P (uint G, uint X, uint P)
		{
			long result = 1;
			long mult = G;

			if (X == 0) 
				return 1;

			while (X != 0) {
				if ((X & 1) != 0) { 
					result = (mult * result) % P; 
				}
				X = X >> 1;
				mult = (mult * mult) % P;
			}
			return (uint)result;
		}
		
		/// <summary>
		/// Magic Transform Thing
		/// </summary>
		protected void KeyTransformValue (ref byte[] stream, uint key, byte keyByte)
		{
			byte[] skey = BitConverter.GetBytes (key);
			
			stream [0] ^= (byte)(stream [0] + skey [0] + keyByte);
			stream [1] ^= (byte)(stream [1] + skey [1] + keyByte);
			stream [2] ^= (byte)(stream [2] + skey [2] + keyByte);
			stream [3] ^= (byte)(stream [3] + skey [3] + keyByte);
			
			stream [4] ^= (byte)(stream [4] + skey [0] + keyByte);
			stream [5] ^= (byte)(stream [5] + skey [1] + keyByte);
			stream [6] ^= (byte)(stream [6] + skey [2] + keyByte);
			stream [7] ^= (byte)(stream [7] + skey [3] + keyByte);
		}
	}
}
