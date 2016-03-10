using System;
using System.IO;

namespace Swiftness.Net
{
	/// <summary>
	/// A single packet representation
	/// </summary>
	public class Packet
	{
		public ushort MsgId
		{
			get;
			set;
		}

		public bool Encrypted
		{
			get;
			set;
		}

		public MemoryStream Payload
		{
			get;
			set;
		}

		public Packet (ushort msgid, bool encrypted, byte[] data)
		{
			this.MsgId = msgid;
			this.Encrypted = encrypted;
			this.Payload = new MemoryStream (data);
		}
	}
}
