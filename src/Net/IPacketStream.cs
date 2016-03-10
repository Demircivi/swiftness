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
	/// [size][payload]
	/// </remarks>
	public interface IPacketStream
	{
		Packet Read ();
		void Write (Packet packet);
		void Flush ();
	}
}
