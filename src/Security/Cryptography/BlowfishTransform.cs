/*
 * This file is part of Swiftness (https://github.com/florian0/swiftness)
 * 
 * Swiftness is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * Swiftness is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with Swiftness.  If not, see <http://www.gnu.org/licenses/>.
 */

using System;
using System.Security.Cryptography;

namespace Swiftness.Security.Cryptography
{
	/// <summary>
	/// Implementation of the Blowfish algorithm
	/// </summary>
	/// <remarks>
	/// Based on the DESTransform code
	/// </remarks>
	public partial class BlowfishTransform : ICryptoTransform
	{
		protected uint[] PArray = new uint[18];
		protected uint[,] SBoxes = new uint[4, 256];
		
		protected bool disposed = false;
		protected bool encrypt;
		
		
		#region Properties
		/// <summary>
		/// Specify if the current transform object can be reused
		/// </summary>
		public virtual bool CanReuseTransform {
			get {
				return true;
			}
		}
		
		/// <summary>
		/// Specify if the current transform object can process multiple blocks in a single call
		/// </summary>
		public virtual bool CanTransformMultipleBlocks {
			get {
				return false;
			}
		}

		/// <summary>
		/// Size of the input block for the function in bytes
		/// </summary>
		public virtual int InputBlockSize {
			get {
				return 8;
			}
		}
		
		/// <summary>
		/// Size of the input block of the function in bytes
		/// </summary>
		public virtual int OutputBlockSize {
			get {
				return 8;
			}
		}
		#endregion
		
		#region Internal Helpers (these were initialy MACROs)
		internal uint S (uint x, byte i)
		{
			if (i < 0 || i > 3) {
				throw new ArgumentOutOfRangeException ("Index i is out of range");
			}
			
			x >>= (24 - (8 * i));
			x &= 0xFF;
			
			return SBoxes [i, x];
		}
		
		internal uint bf_F (uint x)
		{
			return (((S (x, 0) + S (x, 1)) ^ S (x, 2)) + S (x, 3));
		}
		
		/// <summary>
		/// A single blowfish round
		/// </summary>
		/// <param name='a'>
		/// Parameter One
		/// </param>
		/// <param name='b'>
		/// Parameter Two
		/// </param>
		/// <param name='n'>
		/// Index of current round
		/// </param>
		internal uint ROUND (uint a, uint b, int n)
		{
			return a ^ (bf_F (b) ^ PArray [n]);
		}
		
		#endregion
		
		/// <summary>
		/// Initializes a new instance of the <see cref="Swiftness.Security.Cryptography.BlowfishTransform"/> class.
		/// </summary>
		internal BlowfishTransform (Blowfish algo, bool encryption, byte[] key, byte[] iv)
		{
			if (key == null) {
				key = BlowfishTransform.GetStrongKey ();
			}
			
			// if (Blowfish.IsWeakKey (key)) {
			//	throw new CryptographicException ("This is a known weak key.");
			// }
			
			encrypt = encryption;
			
			
			// Load Default P-Box
			for (int i = 0; i < 18; i++) {
				PArray [i] = default_P [i];
			}

			// Load Default S-Boxes
			for (int i = 0; i < 4; i++) {
				for (int s = 0; s < 256; s++)
					SBoxes [i, s] = default_S [i, s];
			}

			// Setup PArray
			byte[] temp = new byte[4];
			int j = 0;
			for (int i = 0; i < 16 + 2; ++i) {
                
				temp [3] = key [j];
				temp [2] = key [(j + 1) % key.Length];
				temp [1] = key [(j + 2) % key.Length];
				temp [0] = key [(j + 3) % key.Length];
                
				PArray [i] ^= BitConverter.ToUInt32 (temp, 0);
				
				j = (j + 4) % key.Length;
			}
			
			uint datal = 0;
			uint datar = 0;

			for (int i = 0; i < 16 + 2; i += 2) {
				Encipher (ref datal, ref datar);
				PArray [i] = datal;
				PArray [i + 1] = datar;
			}

			// Setup SBoxes
			for (int i = 0; i < 4; ++i) {
				for (j = 0; j < 256; j += 2) {
					Encipher (ref datal, ref datar);
					SBoxes [i, j] = datal;
					SBoxes [i, j + 1] = datar;
				}
			}
		}

		/// <summary>
		/// This is the basic blowfish encipher method
		/// </summary>
		/// The 16 rounds have been "loop-unrolled" for speed reasons.
		/// This is valid for C and C++, unsure if it speeds up in C#, too.
		/// </remarks>
		protected virtual void Encipher (ref uint xl, ref uint xr)
		{
			// Make a copy of the parameters
			uint xl_copy = xl;
			uint xr_copy = xr;
			
			xl_copy ^= PArray [0];
			
			
			// Perform 16 rounds of blowfish
			xr_copy = ROUND (xr_copy, xl_copy, 1);
			xl_copy = ROUND (xl_copy, xr_copy, 2);
			
			xr_copy = ROUND (xr_copy, xl_copy, 3);
			xl_copy = ROUND (xl_copy, xr_copy, 4);
			
			xr_copy = ROUND (xr_copy, xl_copy, 5);
			xl_copy = ROUND (xl_copy, xr_copy, 6);
			
			xr_copy = ROUND (xr_copy, xl_copy, 7);
			xl_copy = ROUND (xl_copy, xr_copy, 8);
			
			xr_copy = ROUND (xr_copy, xl_copy, 9);
			xl_copy = ROUND (xl_copy, xr_copy, 10);
			
			xr_copy = ROUND (xr_copy, xl_copy, 11);
			xl_copy = ROUND (xl_copy, xr_copy, 12);
			
			xr_copy = ROUND (xr_copy, xl_copy, 13);
			xl_copy = ROUND (xl_copy, xr_copy, 14);
			
			xr_copy = ROUND (xr_copy, xl_copy, 15);
			xl_copy = ROUND (xl_copy, xr_copy, 16);
			
			xr_copy ^= PArray [17];
			
			// Twisted for reasons :S
			xr = xl_copy;
			xl = xr_copy;
			
		}
		
		/// <summary>
		/// This is the basic blowfish decipher method
		/// </summary>
		/// <remarks>
		/// The 16 rounds have been "loop-unrolled" for speed reasons.
		/// This is valid for C and C++, unsure if it speeds up in C#, too.
		/// </remarks>
		protected virtual void Decipher (ref uint xl, ref uint xr)
		{
			// Make a copy of the parameters
			uint xl_copy = xl;
			uint xr_copy = xr;
			
			xl_copy ^= PArray [17];
			
			// Perform 16 rounds of blowfish
			xr_copy = ROUND (xr_copy, xl_copy, 16);
			xl_copy = ROUND (xl_copy, xr_copy, 15);
			
			xr_copy = ROUND (xr_copy, xl_copy, 14);
			xl_copy = ROUND (xl_copy, xr_copy, 13);
			
			xr_copy = ROUND (xr_copy, xl_copy, 12);
			xl_copy = ROUND (xl_copy, xr_copy, 11);
			
			xr_copy = ROUND (xr_copy, xl_copy, 10);
			xl_copy = ROUND (xl_copy, xr_copy, 9);
			
			xr_copy = ROUND (xr_copy, xl_copy, 8);
			xl_copy = ROUND (xl_copy, xr_copy, 7);
			
			xr_copy = ROUND (xr_copy, xl_copy, 6);
			xl_copy = ROUND (xl_copy, xr_copy, 5);
			
			xr_copy = ROUND (xr_copy, xl_copy, 4);
			xl_copy = ROUND (xl_copy, xr_copy, 3);
			
			xr_copy = ROUND (xr_copy, xl_copy, 2);
			xl_copy = ROUND (xl_copy, xr_copy, 1);
			
			xr_copy ^= PArray [0];
			
			xl = xl_copy;
			xr = xr_copy;
		}
		
		/// <summary>
		/// Transform a block of data
		/// </summary>
		/// <returns>
		/// Number of bytes that were transformed
		/// </returns>
		public int TransformBlock (byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
		{
			if (disposed) {
				throw new ObjectDisposedException ("Object is disposed");
			}
			
			#region Check Input
			if (inputBuffer == null) {
				throw new ArgumentNullException ("inputBuffer");
			}
			
			if (inputOffset < 0) {
				throw new ArgumentOutOfRangeException ("inputOffset", "< 0");
			}
			
			if (inputCount < 0) {
				throw new ArgumentOutOfRangeException ("inputCount", "< 0");
			}
			
			if (inputOffset > inputBuffer.Length - inputCount) {
				throw new ArgumentException ("inputBuffer", "Overflow");
			}
			#endregion
			
			#region Check Output
			if (outputBuffer == null) {
				throw new ArgumentNullException ("outputBuffer");
			}
			
			if (outputOffset < 0) {
				throw new ArgumentOutOfRangeException ("outputOffset", "< 0");
			}
			/// TODO: Check for output overflow
			#endregion
			
			// Determine, if this instance is an encryptor or a decryptor
			if (encrypt) {
				return EncipherBlock (inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset);
			} else {
				return DecipherBlock (inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset);
			}
		}
		
		/// <summary>
		/// Enciphers the stream of data
		/// </summary>
		/// <returns>
		/// Number of bytes that were transformed
		/// </returns>
		protected int EncipherBlock (byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
		{
			int outputSize = GetOutputLength (inputCount);
			
			byte[] buffer = new byte[outputSize];
			
			Buffer.BlockCopy (inputBuffer, inputOffset, buffer, 0, inputCount);
			
			for (int i = 0; i < inputCount; i += 8) {
				// Get Xl and Xr
				uint xl = BitConverter.ToUInt32 (buffer, i);
				uint xr = BitConverter.ToUInt32 (buffer, i + 4);
				
				
				this.Encipher (ref xl, ref xr);
				
				
				// Store Xl and Xr to buffer
				Buffer.BlockCopy (BitConverter.GetBytes (xl), 0, outputBuffer, outputOffset + i, 4);
				Buffer.BlockCopy (BitConverter.GetBytes (xr), 0, outputBuffer, outputOffset + i + 4, 4);
			}
			
			return outputSize;
		}
		

		/// <summary>
		/// Deciphers the stream of data
		/// </summary>
		/// <returns>
		/// Number of bytes that were transformed
		/// </returns>
		protected int DecipherBlock (byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
		{
			int outputSize = GetOutputLength (inputCount);
			
			byte[] buffer = new byte[outputSize];
			
			Buffer.BlockCopy (inputBuffer, inputOffset, buffer, 0, inputCount);
			
			
			for (int i = 0; i < inputCount; i += 8) {
				// Get Xl and Xr
				uint xl = BitConverter.ToUInt32 (buffer, i);
				uint xr = BitConverter.ToUInt32 (buffer, i + 4);
				
				
				this.Decipher (ref xl, ref xr);
				
				
				// Store Xl and Xr to buffer
				Buffer.BlockCopy (BitConverter.GetBytes (xl), 0, outputBuffer, outputOffset + i, 4);
				Buffer.BlockCopy (BitConverter.GetBytes (xr), 0, outputBuffer, outputOffset + i + 4, 4);
			}
			
			return outputSize;
		}
		
		
		/// <summary>
		/// Processes the final part of the data. Also finalizes the function if needed.
		/// </summary>
		public byte[] TransformFinalBlock (byte[] inputBuffer, int inputOffset, int inputCount)
		{
			throw new NotImplementedException ();
		}
		
		public void Dispose ()
		{
			disposed = true;
			// Cleanup remaining keys, ivs, stuff that should not stay in memory
		}
		
		/// <summary>
		/// Generate a random strong key
		/// </summary>
		/// <returns>
		/// The Blowfish Key
		/// </returns>
		/// <remarks>
		/// I dont feel like putting a random algo in here yet.
		/// </remarks>
		internal static byte[] GetStrongKey ()
		{
			return new byte[] { 0x32, 0xCE, 0xDD, 0x7C, 0xBC, 0xA8 };
		}
		
		/// <summary>
		/// Get output length of the blowfish-transformation 
		/// </summary>
		/// <remarks>
		/// This will match the input length fit the last transformed
		/// block. This is needed, since blowfish will transform at 
		/// least 8 bytes
		/// </remarks>
		internal int GetOutputLength (int lInputLong)
		{
			int lVal = lInputLong % 8;
			
			if (lVal != 0) {
				return lInputLong + 8 - lVal;
			} else {
				return lInputLong;
			}
		}
	}
}

