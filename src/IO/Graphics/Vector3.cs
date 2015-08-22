using System;

namespace Swiftness.IO.Graphics
{
	public struct Vector3
	{
		public float X, Y, Z;
		
		public Vector3 (float x, float y, float z)
		{
			X = x;
			Y = y;
			Z = z;
		}
		
		public override string ToString ()
		{
			return string.Format ("[Vector3] {{ X = {0}, Y = {1}, Z = {2} }}", X, Y, Z);
		}
	}
}

