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
	public class BlowfishManaged : Blowfish
	{
		public BlowfishManaged ()
		{
			/* Allow 32 to 448 bit keys */
			LegalKeySizesValue = new KeySizes[] { new KeySizes (32, 448, 0) };
			
			/* Allow 8 byte blocks */
			LegalBlockSizesValue = new KeySizes[] { new KeySizes (64, 64, 0) };
		}
		
		public override ICryptoTransform CreateEncryptor (byte[] rgbKey, byte[] rgbIV)
		{
			return new BlowfishTransform (this, true, rgbKey, rgbIV);
		}
		
		public override ICryptoTransform CreateDecryptor (byte[] rgbKey, byte[] rgbIV)
		{
			return new BlowfishTransform (this, false, rgbKey, rgbIV);
		}
		
		public override void GenerateKey ()
		{
			throw new System.NotImplementedException ();
		}
		
		public override void GenerateIV ()
		{
			throw new NotSupportedException ("IVs are not supported");
		}
	}
}
