using System;
namespace Swiftness.Net
{
	internal class Counter
	{
		byte[] count_byte_seeds = new byte[3];// Count byte seeds

		// Function called to generate a count byte
		// This function was written by jMerlin as part of the article "How to generate the security bytes for SRO"
		public byte GenerateCountByte ()
		{
			byte result = (byte)(count_byte_seeds[2] * (~count_byte_seeds[0] + count_byte_seeds[1]));
			result = (byte)(result ^ (result >> 4));
			count_byte_seeds[0] = result;
			return result;
		}

		public Counter (uint seed)
		{
			// This function was written by jMerlin as part of the article "How to generate the security bytes for SRO"
			if (seed == 0)
			{
				seed = 0x9ABFB3B6;
			}

			uint mut = seed;
			uint mut1 = GenerateValue (ref mut);
			uint mut2 = GenerateValue (ref mut);
			uint mut3 = GenerateValue (ref mut);
			GenerateValue (ref mut);

			byte byte1 = (byte)((mut & 0xFF) ^ (mut3 & 0xFF));
			byte byte2 = (byte)((mut1 & 0xFF) ^ (mut2 & 0xFF));

			if (byte1 == 0)
				byte1 = 1;

			if (byte2 == 0)
				byte2 = 1;

			count_byte_seeds[0] = (byte)(byte1 ^ byte2);
			count_byte_seeds[1] = byte2;
			count_byte_seeds[2] = byte1;
		}



		// This function was written by jMerlin as part of the article "How to generate the security bytes for SRO"
		// Simplified by Bueddl
		private uint GenerateValue (ref uint val)
		{
			// Orig:
			//for (int i = 0; i < 32; i++)
			//	val = (((((((((((val >> 2) ^ val) >> 2) ^ val) >> 1) ^ val) >> 1) ^ val) >> 1) ^ val) & 1) | ((((val & 1) << 31) | (val >> 1)) & 0xFFFFFFFE);
			//return val;

			uint part;

			for (int i = 0; i < 32; i++)
			{
				// Bits 31-1
				part = val >> 1;        // Bits 30-1

				if (val % 2 == 1)
				{
					part |= 0x80000000; // Bit 31
				}

				part &= 0xFFFFFFFE;

				// Bit 0
				if (((val >> 7) ^ (val >> 5) ^ (val >> 3) ^ (val >> 2) ^ (val >> 1) ^ val) % 2 == 1)
					part |= 1;          // Bit 0

				val = part;
			}

			return val;


			/* (((val >> 2) ^ val) >> 2) ^ val
            000000
            000001
             */

			/* (val >> 2) ^ val
            0000 0000  0->0
            0001 0001  1->1
            0010 0010  2->2
            0011 0011  3->3
            0100 0001  4->1
            0101 0000  5->0
            0110 0011  6->3
            0111 0010  7->2
            1000 0010  8->2
            1001 0011  9->3
            1010 0000 10->0
            1011 0001 11->1
            1100 0011 12->3
            1101 0010 13->2
            1110 0001 14->1
            1111 0000 15->0
            */

			/* (val >> 1) ^ val
            00 00
            01 01
            10 01
            11 00
            */
		}
	}
}

