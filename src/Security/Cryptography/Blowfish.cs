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
	public abstract class Blowfish : SymmetricAlgorithm
	{	
		/// <summary>
		/// Create a new Blowfish Instance
		/// </summary>
		/// <remarks>In Microsoft's fantasy, this function should use the typename
		/// for instanciation. Type.GetType does not work with types that are 
		/// outside of mscorlib. Wonderful</remarks>
		public new static Blowfish Create ()
		{
			return new BlowfishManaged ();
		}
		
		/// <summary>
		/// reate a new Blowfish Instance (not working)
		/// </summary>
		/// <remarks>
		/// Creating a self defined type by typename is impossible. Use Create() instead!
		/// </remarks>
		public new static Blowfish Create (string str)
		{
			throw new NotSupportedException ("This function is not available");
		}
		
		public static bool IsWeakKey (byte[] rgbKey)
		{
			throw new NotImplementedException ();
		}
	}
}
