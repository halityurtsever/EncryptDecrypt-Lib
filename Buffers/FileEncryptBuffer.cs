using System;
using System.Text;

namespace TextEncryptDecrypt.Buffers
{
    internal sealed class FileEncryptBuffer : BaseEncryptBuffer
    {
        //################################################################################
        #region Constructor

        public FileEncryptBuffer(string extension, string password, byte[] initBuffer, byte[] saltBuffer, byte[] encryptedBuffer) :
            base(password, initBuffer, saltBuffer, encryptedBuffer)
        {
            ExtensionLength = extension.Length;
            ExtensionBuffer = Encoding.UTF8.GetBytes(extension);
        }

        #endregion

        //################################################################################
        #region Properties

        private int ExtensionLength { get; }

        private byte[] ExtensionBuffer { get; }

        #endregion

        //################################################################################
        #region Internal Members

        internal byte[] CombineBuffer()
        {
            PreconditionCheck();

            var combinedBufferLength = 0;
            combinedBufferLength += Constants.Int32Length;  //length of file extension
            combinedBufferLength += ExtensionBuffer.Length;
            combinedBufferLength += Constants.Int32Length;  //length of password
            combinedBufferLength += PasswordBuffer.Length;
            combinedBufferLength += InitBuffer.Length;
            combinedBufferLength += SaltBuffer.Length;
            combinedBufferLength += Constants.Int32Length;  //length of encrypted data
            combinedBufferLength += EncryptedBuffer.Length;

            var position = 0;
            CombinedBuffer = new byte[combinedBufferLength];
            var extensionLengthBuffer = BitConverter.GetBytes(ExtensionLength);

            //write extension length
            Buffer.BlockCopy(extensionLengthBuffer, 0, CombinedBuffer, position, extensionLengthBuffer.Length);
            position += extensionLengthBuffer.Length;

            //write extension buffer
            Buffer.BlockCopy(ExtensionBuffer, 0, CombinedBuffer, position, ExtensionBuffer.Length);
            position += ExtensionBuffer.Length;

            CreateCombinedBuffer(position);

            return CombinedBuffer;
        }

        #endregion

        //################################################################################
        #region Base Class Overrides

        protected override void PreconditionCheck()
        {
            if (ExtensionBuffer == null) throw new ArgumentException($"Corrupted buffer: {nameof(ExtensionBuffer)}");

            base.PreconditionCheck();
        }

        #endregion
    }
}
