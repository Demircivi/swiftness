using System;

namespace Swiftness.IO.Graphics
{
	public class Vector4
	{
		float W, X, Y, Z;
		
		public Vector4 (float w, float x, float y, float z)
		{
			W = w;
			X = x;
			Y = y;
			Z = z;
		}
		
		public override string ToString ()
		{
			return string.Format ("[Vector4] {{ X = {0}, Y = {1}, Z = {2}, W = {3} }}", X, Y, Z, W);
		}
	}
}

