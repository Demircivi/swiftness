using System;
using System.Net.Sockets;

using System.IO;

namespace Swiftness.Net
{
	/// <summary>
	/// basic abstract interface for reading and writing silkroad packets on
	/// a network stream
	/// </summary>
	/// <remarks>
	/// This is no longer an specialization of NetworkStream since
	/// it makes no sense to implement byte[]-based reading or writing.
	/// 
	/// This class should only read the absolute base packet:
	/// [size][opcode][count][crc][payload]
	/// </remarks>
	public abstract class PacketStream
	{
		protected NetworkStream InnerStream {
			get;
			private set;
		}
		
		public PacketStream (NetworkStream stream)
		{
			this.InnerStream = stream;
		}
		
		public abstract Packet Read();
		public abstract void Write(Packet packet);
		public abstract void Flush();
	}
}
