namespace TextEncryptDecrypt.Buffers
{
    internal sealed class TextEncryptBuffer : BaseEncryptBuffer
    {
        //################################################################################
        #region Constructor

        public TextEncryptBuffer(string password, byte[] initBuffer, byte[] saltBuffer, byte[] encryptedBuffer) :
            base(password, initBuffer, saltBuffer, encryptedBuffer)
        {

        }

        #endregion

        //################################################################################
        #region Internal Members

        internal byte[] CombineBuffer()
        {
            PreconditionCheck();

            var combinedBufferLength = 0;
            combinedBufferLength += Constants.Int32Length;  //length of password
            combinedBufferLength += PasswordBuffer.Length;
            combinedBufferLength += InitBuffer.Length;
            combinedBufferLength += SaltBuffer.Length;
            combinedBufferLength += Constants.Int32Length;  //length of encrypted data
            combinedBufferLength += EncryptedBuffer.Length;

            var position = 0;
            CombinedBuffer = new byte[combinedBufferLength];

            CreateCombinedBuffer(position);

            return CombinedBuffer;
        }

        #endregion
    }
}
