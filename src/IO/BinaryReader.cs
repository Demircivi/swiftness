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

		/// <remarks>
		/// Format: [4 Byte Length][X Byte String]
		/// Its possible to read empty strings (length == 0)
		/// </remarks>
		/// <summary>
		/// Reads a string from the stream using Joymax-binary-formatting.
		/// </summary>
		/// <returns>
		/// The string.
		/// </returns>
		public override string ReadString ()
		{
			int len = this.ReadInt32 ();
			
			// Return an empty string, if there is no string to read
			if (len == 0) {
				return string.Empty;
			}
			
			// Ignore negative lengths
			// (Remark: The length could be unsigned integer, that would make sense. But i could
			//          not find any evidence.)
			if (len <= 0) {
				throw new System.IO.IOException("Format Error: String length must be greater than 0");
			}
			
			return new string(this.ReadChars(len));
		}
	}
}
