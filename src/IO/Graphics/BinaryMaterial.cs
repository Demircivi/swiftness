using System;
using System.Collections.Generic;

using Swiftness.IO;

namespace Swiftness.IO.Graphics
{
	/// <summary>
	/// This file can read the Joymax Binary Material Format
	/// </summary>
	/// <see cref="https://github.com/florian0/swiftness/wiki/Material-File-Format-%28.bmt%29"/>
	public class BinaryMaterial
	{
		public class Material 
		{
			public string Name;
			public string File;
			
			public int Flags;
			
			public float[] Unknown = new float[16];
		}
		
		/// <summary>
		/// Gets or sets the list of materials.
		/// </summary>
		public List<Material> Materials {
			get;
			set;
		}
		
		/// <summary>
		/// Load the specified material from file
		/// </summary>
		/// <param name='path'>
		/// Absolute or relative path to the file
		/// </param>
		public static BinaryMaterial Load (string path)
		{
			/* Parse File */
			return Load (new System.IO.FileStream (path, System.IO.FileMode.Open));
		}
		
		/// <summary>
		/// Load the specified material from stream
		/// </summary>
		/// <param name='stream'>
		/// Readable stream containing the material
		/// </param>
		public static BinaryMaterial Load (System.IO.Stream stream)
		{
			Swiftness.IO.BinaryReader reader = new Swiftness.IO.BinaryReader (stream);
			
			#region Read and validate header

			// The header consists of two parts, separated by a whitespace:
			// - The Filetype (e.g. JMXVRES)
			// - The Version (e.g. 0109)
			string header = new string (reader.ReadChars (0xC));
			string[] parts = header.Split (' ');

			// Check the type
			if (parts [0] != "JMXVBMT") {
				throw new Exception ("Invalid File Format (" + parts [0] + ")");
			}

			// Check the version
			if (parts [1] != "0102") {
				throw new Exception ("Unsupported Version (" + parts [1] + ")");
			}
			#endregion
			
			BinaryMaterial bmat = new BinaryMaterial ();
			
			int textureCount = reader.ReadInt32 ();
			
			for (int i = 0; i < textureCount; i++) {
				
				Material mat = new Material ();
				
				mat.Name = reader.ReadString ();
				
				for (int u = 0; u < 16; u++) {
					mat.Unknown [u] = reader.ReadSingle ();
				}
				
				byte[] unk1 = reader.ReadBytes (4);
				
				mat.Flags = reader.ReadInt32 ();
				
				mat.File = reader.ReadString ();
				
				byte[] unk2 = reader.ReadBytes (7);
				
				
				bmat.AddMaterial (mat);
			}
			
			return bmat;
		}
		
		public BinaryMaterial ()
		{
			Materials = new List<Material> ();
		}
		
		/// <summary>
		/// Adds a material to the list
		/// </summary>
		public void AddMaterial (Material mat)
		{
			Materials.Add (mat);
		}
	}
}

