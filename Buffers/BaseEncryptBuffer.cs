using System;
using System.Text;

namespace TextEncryptDecrypt.Buffers
{
    internal abstract class BaseEncryptBuffer
    {
        //################################################################################
        #region Constructor

        protected BaseEncryptBuffer(string password, byte[] initBuffer, byte[] saltBuffer, byte[] encryptedBuffer)
        {
            PasswordLength = password.Length;
            PasswordBuffer = Encoding.UTF8.GetBytes(password);
            InitBuffer = initBuffer;
            SaltBuffer = saltBuffer;
            EncryptedBufferLength = encryptedBuffer.Length;
            EncryptedBuffer = encryptedBuffer;
        }

        #endregion

        //################################################################################
        #region Properties

        protected int PasswordLength { get; set; }

        protected byte[] PasswordBuffer { get; set; }

        protected byte[] InitBuffer { get; set; }

        protected byte[] SaltBuffer { get; set; }

        protected int EncryptedBufferLength { get; set; }

        protected byte[] EncryptedBuffer { get; set; }

        protected byte[] CombinedBuffer { get; set; }

        #endregion

        //################################################################################
        #region Protected Members

        protected void CreateCombinedBuffer(int position)
        {
            var passwordLengthBuffer = BitConverter.GetBytes(PasswordLength);
            var encryptedLengthBuffer = BitConverter.GetBytes(EncryptedBufferLength);

            //write password length
            Buffer.BlockCopy(passwordLengthBuffer, 0, CombinedBuffer, position, passwordLengthBuffer.Length);
            position += passwordLengthBuffer.Length;

            //write password buffer
            Buffer.BlockCopy(PasswordBuffer, 0, CombinedBuffer, position, PasswordBuffer.Length);
            position += PasswordBuffer.Length;

            //write init buffer
            Buffer.BlockCopy(InitBuffer, 0, CombinedBuffer, position, InitBuffer.Length);
            position += InitBuffer.Length;

            //write salt buffer
            Buffer.BlockCopy(SaltBuffer, 0, CombinedBuffer, position, SaltBuffer.Length);
            position += SaltBuffer.Length;

            //write encrypted buffer length
            Buffer.BlockCopy(encryptedLengthBuffer, 0, CombinedBuffer, position, encryptedLengthBuffer.Length);
            position += encryptedLengthBuffer.Length;

            //write encrypted buffer
            Buffer.BlockCopy(EncryptedBuffer, 0, CombinedBuffer, position, EncryptedBuffer.Length);
        }

        protected virtual void PreconditionCheck()
        {
            if (PasswordBuffer == null) throw new ArgumentException($"Corrupted buffer: {nameof(PasswordBuffer)}");

            if (InitBuffer == null) throw new ArgumentException($"Corrupted buffer: {nameof(InitBuffer)}");

            if (SaltBuffer == null) throw new ArgumentException($"Corrupted buffer: {nameof(SaltBuffer)}");

            if (EncryptedBuffer == null) throw new ArgumentException($"Corrupted buffer: {nameof(EncryptedBuffer)}");
        }

        #endregion
    }
}
