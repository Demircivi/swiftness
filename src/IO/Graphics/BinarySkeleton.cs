using System;
using System.Collections.Generic;

namespace Swiftness.IO.Graphics
{
	/// <summary>
	/// This class can read the Joymax Binary Skeleton Format
	/// </summary>
	/// <see cref="https://github.com/florian0/swiftness/wiki/Skeleton-File-Format-%28.bsk%29"/>
	public class BinarySkeleton
	{
		/// <summary>
		/// Represents a single bone
		/// </summary>
		public class Bone {
			
			/// <summary>
			/// Gets or sets name of the parent bone
			/// </summary>
			public string Parent {
				get;
				set;
			}
			
			/// <summary>
			/// Gets or sets the name of the bone
			/// </summary>
			public string Name {
				get;
				set;
			}
			
			/// <summary>
			/// Gets the bones with same parent.
			/// </summary>
			public List<string> BonesWithSameParent {
				get;
				protected set;
			}
			
			public Vector4 RotationToParent {
				get;
				set;
			}
			
			public Vector3 TranslationToParent {
				get;
				set;
			}
			
			
			public Vector4 RotationToOrigin {
				get;
				set;
			}
			
			public Vector3 TranslationToOrigin {
				get;
				set;
			}
			
			
			public Vector4 RotationToUnknown {
				get;
				set;
			}
			
			public Vector3 TranslationToUnknown {
				get;
				set;
			}
			
			public byte Unknown {
				get;
				set;
			}
			
			public Bone() {
				BonesWithSameParent = new List<string> ();	
			}
			
		}
		
		/// <summary>
		/// Gets or sets the bones in the skeleton
		/// </summary>
		public List<Bone> Bones {
			get;
			protected set;
		}
		
		public int Unknown1 {
			get;
			protected set;
		}
		
		public int Unknown2 {
			get;
			protected set;
		}
		
		public int Unknown3 {
			get;
			protected set;
		}
		
		
		/// <summary>
		/// Load the specified material from file
		/// </summary>
		/// <param name='path'>
		/// Absolute or relative path to the file
		/// </param>
		public static BinarySkeleton Load (string path)
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
		public static BinarySkeleton Load (System.IO.Stream stream)
		{
			Swiftness.IO.BinaryReader reader = new Swiftness.IO.BinaryReader (stream);
			
			#region Read and validate header

			// The header consists of two parts, separated by a whitespace:
			// - The Filetype (e.g. JMXVRES)
			// - The Version (e.g. 0109)
			string header = new string (reader.ReadChars (0xC));
			string[] parts = header.Split (' ');

			// Check the type
			if (parts [0] != "JMXVBSK") {
				throw new Exception ("Invalid File Format (" + parts [0] + ")");
			}

			// Check the version
			if (parts [1] != "0101") {
				throw new Exception ("Unsupported Version (" + parts [1] + ")");
			}
			#endregion
			
			BinarySkeleton skeleton = new BinarySkeleton ();
			
			int boneCount = reader.ReadInt32 ();
			
			for (int boneId = 0; boneId < boneCount; boneId++) {
				
				Bone bone = new Bone ();
				
				if (boneId != 0) {
					int subBoneCount = reader.ReadInt32 ();
					
					for (int subBone = 0; subBone < subBoneCount; subBone++) {
						string subBoneName = reader.ReadString ();
						
						bone.BonesWithSameParent.Add (subBoneName);
					}
				}
				
				bone.Unknown = reader.ReadByte ();
				
				bone.Name = reader.ReadString ();
				bone.Parent = reader.ReadString ();
				
				bone.RotationToParent = reader.ReadVector4 ();
				bone.TranslationToParent = reader.ReadVector3 ();
				
				bone.RotationToOrigin = reader.ReadVector4 ();
				bone.TranslationToOrigin = reader.ReadVector3 ();
	
				bone.RotationToUnknown = reader.ReadVector4 ();
				bone.TranslationToUnknown = reader.ReadVector3 ();
				
				skeleton.Bones.Add (bone);
				
			}
			
			skeleton.Unknown1 = reader.ReadInt32 ();
			skeleton.Unknown2 = reader.ReadInt32 ();
			skeleton.Unknown3 = reader.ReadInt32 ();
			
			return skeleton;
		}
		
		public BinarySkeleton ()
		{
			Bones = new List<Bone> ();
		}
	}
}

