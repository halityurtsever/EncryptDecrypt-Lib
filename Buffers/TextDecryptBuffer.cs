namespace TextEncryptDecrypt.Buffers
{
    internal sealed class TextDecryptBuffer : BaseDecryptBuffer
    {
        //################################################################################
        #region Constructor

        public TextDecryptBuffer(byte[] combinedBuffer) : base(combinedBuffer)
        {

        }

        #endregion

        //################################################################################
        #region Internal Members

        internal byte[] ParseBuffer()
        {
            return ParseCombinedBuffer();
        }

        #endregion
    }
}
