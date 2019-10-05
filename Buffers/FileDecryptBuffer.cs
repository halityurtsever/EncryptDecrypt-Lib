using System;
using System.Text;

namespace TextEncryptDecrypt.Buffers
{
    internal sealed class FileDecryptBuffer : BaseDecryptBuffer
    {
        //################################################################################
        #region Constructor

        public FileDecryptBuffer(byte[] combinedBuffer) : base(combinedBuffer)
        {

        }

        #endregion

        //################################################################################
        #region Properties

        public string DecryptedExtension { get; private set; }

        #endregion

        //################################################################################
        #region Internal Members

        internal byte[] ParseBuffer()
        {
            var position = 0;

            //read file extension length
            var extensionLengthBuffer = new byte[Constants.Int32Length];
            Buffer.BlockCopy(CombinedBuffer, position, extensionLengthBuffer, 0, extensionLengthBuffer.Length);
            position += extensionLengthBuffer.Length;

            //read file extension
            var extensionLength = BitConverter.ToInt32(extensionLengthBuffer, 0);
            var extensionBuffer = new byte[extensionLength];
            Buffer.BlockCopy(CombinedBuffer, position, extensionBuffer, 0, extensionBuffer.Length);
            DecryptedExtension = Encoding.UTF8.GetString(extensionBuffer);
            position += extensionBuffer.Length;

            return ParseCombinedBuffer(position);
        }

        #endregion
    }
}
