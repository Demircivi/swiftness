using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;

using System.Threading;

using Swiftness.Security.Cryptography;

namespace Swiftness.Net
{
    /// <summary>
    /// Generic stream implementing the silkroad protocol.
    /// </summary>
    /// <remarks>
    /// This class is abstract because it does not contain any authentication
    /// mechanism.
    /// Use SilkroadClientStream or SilkroadServerStream instead
    /// </remarks>
    public abstract class SilkroadStream : IPacketStream
    {
        internal struct Payload
        {
            public byte[] Data;

            public byte[] len;

            public short Length
            {
                get
                {
                    return (short)(0x7FF & BitConverter.ToInt16(len, 0));
                }
            }

            public bool Encrypted
            {
                get
                {
                    short length = BitConverter.ToInt16(len, 0);

                    if ((length & 0x8000) == 0x8000)
                    {
                        return true;
                    }

                    return false;
                }
            }
        }

        protected CRC crc;
        internal Counter counter;

        protected Blowfish blowfish;
        protected ICryptoTransform encryptor;
        protected ICryptoTransform decryptor;

        internal NetworkStream InnerStream;

        internal Queue<Packet> PacketQueue = new Queue<Packet>();

        internal ManualResetEvent waitPacketReceive = new ManualResetEvent(false);

        public AuthenticationState AuthenticationState
        {
            get;
            internal set;
        }

        public SilkroadStream(NetworkStream stream)
        {
            InnerStream = stream;
            blowfish = Blowfish.Create();
            AuthenticationState = AuthenticationState.NONE;
        }

        public abstract void Authenticate();

        /// <summary>
        /// Begin to read the 2 byte length from the stream (async)
        /// </summary>
        protected void BeginReadLength()
        {
            Payload p = new Payload();
            p.len = new byte[2];

            InnerStream.BeginRead(p.len, 0, 2, new AsyncCallback(OnLengthRead), p);
        }

        /// <summary>
        /// Begin to read x byte payload from the stream (async)
        /// </summary>
        /// <param name="p"></param>
        private void BeginReadData(Payload p)
        {
            p.Data = new byte[p.Length + 4];
            InnerStream.BeginRead(p.Data, 0, p.Length + 4, new AsyncCallback(OnDataRead), p);
        }

        /// <summary>
        /// Async callback for BeginReadLength
        /// </summary>
        /// <param name="result"></param>
        private void OnLengthRead(IAsyncResult result)
        {
            int bytesRead = InnerStream.EndRead(result);

            if (bytesRead != 2)
            {
                throw new IOException("Invalid number of bytes received");
            }

            Payload p = (Payload)result.AsyncState;

            // No need to split here, encrypted flag in p
            // Correct conversion of length is done by property-getter
            BeginReadData(p);
        }

        /// <summary>
        /// Async callback for BeginReadData
        /// </summary>
        /// <param name="result"></param>
        private void OnDataRead(IAsyncResult result)
        {
            int bytesRead = InnerStream.EndRead(result);

            Payload p = (Payload)result.AsyncState;

            if (bytesRead != p.Length + 4)
            {
                throw new IOException("Invalid number of bytes received");
            }

            if (p.Encrypted)
            {
                if (!(this.AuthenticationState == AuthenticationState.DONE))
                    throw new Exception("Encrypted packet received before handshake");

                // Decrypt
                throw new NotImplementedException("Decryption is not available yet");

            }

            ushort msgid = BitConverter.ToUInt16(p.Data, 0);

            // Received CRC and Count is always zero, no way to check it ?
            // byte count = p.Data[2];
            // byte crc = p.Data[3];
            
            // Cut off unwanted data
            //ArraySegment<byte> segment = new ArraySegment<byte>(p.Data, 4, p.Data.Length - 4);

            byte[] payload = new byte[p.Data.Length - 4];

            Array.ConstrainedCopy(p.Data, 4, payload, 0, p.Data.Length - 4);
            


            // Handle Packet
            HandlePacket(new Packet(msgid, p.Encrypted, payload));

            // Get next packet
            BeginReadLength();
        }

        /// <summary>
        /// Called for every packet received.
        /// </summary>
        /// <param name="p"></param>
        private void HandlePacket(Packet p)
        {
            
            if (p.MsgId == 0x5000)
            {
                // Handle handshake
                HandleHandshake(p);
            }
            else
            {
                // Simply pass packet on
                OnNewPacket(p);
            }
        }

        protected abstract void HandleHandshake(Packet p);

        /// <summary>
        /// Called for every new packet after filtering. 
        /// </summary>
        /// <remarks>Override for possible event-based implementation</remarks>
        /// <param name="packet"></param>
        protected virtual void OnNewPacket(Packet packet)
        {
            lock (PacketQueue)
            {
                PacketQueue.Enqueue(packet);
                waitPacketReceive.Set();
            }
        }

        /// <summary>
        /// Receive one packet. Blocking.
        /// </summary>
        /// <returns></returns>
        public virtual Packet Read()
        {
            lock (PacketQueue)
            {
                if (PacketQueue.Count == 0)
                {
                    waitPacketReceive.Reset();
                }
            }

            waitPacketReceive.WaitOne();
            return PacketQueue.Dequeue();
        }

        public virtual void Write(Packet packet)
        {
            lock (this)
            {
                // Calculate Security Count
                byte count = this.counter.GenerateCountByte();

                // Build Byte[] from Packet
                MemoryStream ms = new MemoryStream();
                BinaryWriter writer = new BinaryWriter(ms);

                ushort len = (ushort)packet.Payload.Length;

                // Set encrypted-flag if packet is encrypted
                if (packet.Encrypted)
                    len |= 0x8000;


                // [2 len][2 op][count][crc]
                writer.Write(len);
                writer.Write(packet.MsgId);
                writer.Write(count);
                writer.Write((byte)0);
                writer.Flush();

                packet.Payload.WriteTo(ms);


                // Calculate CRC
                byte checksum = this.crc.Calculate(ms.ToArray());

                writer.Seek(5, SeekOrigin.Begin);
                writer.Write(checksum);


                Console.WriteLine(
                "[PacketStream] C->S [{0:X4}][{1:X4}][{2:X2}][{3:X2}]",
                len,
                packet.MsgId,
                checksum,
                count);


                // Write Packet to Stream
                this.InnerStream.Write(ms.ToArray(), 0, (int)ms.Length);
            }
        }

        public void Flush()
        {
            throw new System.NotImplementedException();
        }


        /// <summary>
        /// Fast way to calculate G^X % P without overflowing datatypes
        /// </summary>
        /// <remarks>
        /// This function was written by jMerlin as part of the article "How to generate the security bytes for SRO".
        /// </remarks>
        protected uint G_pow_X_mod_P(uint G, uint X, uint P)
        {
            long result = 1;
            long mult = G;

            if (X == 0)
                return 1;

            while (X != 0)
            {
                if ((X & 1) != 0)
                {
                    result = (mult * result) % P;
                }
                X = X >> 1;
                mult = (mult * mult) % P;
            }
            return (uint)result;
        }

        /// <summary>
        /// Magic Transform Thing
        /// </summary>
        protected void KeyTransformValue(ref byte[] stream, uint key, byte keyByte)
        {
            byte[] skey = BitConverter.GetBytes(key);

            stream[0] ^= (byte)(stream[0] + skey[0] + keyByte);
            stream[1] ^= (byte)(stream[1] + skey[1] + keyByte);
            stream[2] ^= (byte)(stream[2] + skey[2] + keyByte);
            stream[3] ^= (byte)(stream[3] + skey[3] + keyByte);

            stream[4] ^= (byte)(stream[4] + skey[0] + keyByte);
            stream[5] ^= (byte)(stream[5] + skey[1] + keyByte);
            stream[6] ^= (byte)(stream[6] + skey[2] + keyByte);
            stream[7] ^= (byte)(stream[7] + skey[3] + keyByte);
        }
    }
}
