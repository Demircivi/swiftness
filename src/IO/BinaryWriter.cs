using System;
using System.Text;

namespace Swiftness.IO
{
	public class BinaryWriter : System.IO.BinaryWriter
	{
		public BinaryWriter (System.IO.Stream input)
			: base (input)
		{ }

		public BinaryWriter (System.IO.Stream input, Encoding encoding)
			: base (input, encoding)
		{ }

		/// <remarks>
		/// Format: [4 Byte Length][X Byte String]
		/// Its possible to write empty strings (length == 0)
		/// </remarks>
		/// <summary>
		/// Writes a string to the stream using Joymax-binary-formatting.
		/// </summary>
		/// <param name='value'>
		/// The string to be written
		/// </param>
		public override void Write (string value)
		{
			int len = value.Length;
			this.Write (len);

			for (int i = 0; i < value.Length; i++)
			{
				this.Write (value[i]);
			}
		}

	}
}

