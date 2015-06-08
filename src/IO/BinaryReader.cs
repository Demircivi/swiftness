using System;
using System.Text;

namespace Swiftness.IO
{
	/// <summary>
	/// A BinaryReader abstraction that reads strings correctly
	/// </summary>
	class BinaryReader : System.IO.BinaryReader
	{
		public BinaryReader(System.IO.Stream input) 
			: base(input) { }

		public BinaryReader(System.IO.Stream input, Encoding encoding)
			: base(input, encoding) { }


		public override string ReadString()
		{
			int len = this.ReadInt32();
				return new string(this.ReadChars(len));
		}
	}
}
