using System;
using System.IO;

namespace Swiftness.Net
{
	/// <summary>
	/// A single packet representation
	/// </summary>
	public class Packet
	{
		public short OpCode {
			get;
			set;
		}
		
		public MemoryStream Payload {
			get;
			set;
		}
		
		public byte CRC {
			get;
			set;
		}
		
		public byte SecurityCount {
			get;
			set;
		}
		
		public bool Encrypted {
			get;
			set;
		}
		
		public Packet ()
		{
		}
		
	}
}

