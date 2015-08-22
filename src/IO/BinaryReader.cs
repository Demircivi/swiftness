using System;
using System.Text;

using Swiftness.IO.Graphics;

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
		
		public string ReadString (int length)
		{
			return new string (this.ReadChars (length));
		}
		
		/// <summary>
		/// Reads a vector3 from stream
		/// </summary>
		/// <returns>
		/// The vector3.
		/// </returns>
		public Vector3 ReadVector3 () {
			float x = this.ReadSingle();
			float y = this.ReadSingle();
			float z = this.ReadSingle();
			
			return new Vector3 (x, y, z);
		}
		
		/// <summary>
		/// Reads a vector4 from stream
		/// </summary>
		/// <returns>
		/// The vector4.
		/// </returns>
		public Vector4 ReadVector4 ()
		{
			float x = this.ReadSingle ();
			float y = this.ReadSingle ();
			float z = this.ReadSingle ();
			float w = this.ReadSingle();
			
			return new Vector4 (w, x, y, z);
		}
	}
}
