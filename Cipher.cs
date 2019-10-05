using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

using TextEncryptDecrypt.Buffers;

namespace TextEncryptDecrypt
{
    public class Cipher
    {
        //################################################################################
        #region Constructor

        public Cipher() : this(HashAlgorithm.SHA256)
        { }

        public Cipher(HashAlgorithm hashAlgorithm)
        {
            HashAlgorithm = hashAlgorithm;
            SaltBuffer = CreateInitSaltBuffer();
            InitBuffer = CreateInitSaltBuffer();
        }

        #endregion

        //################################################################################
        #region Properties

        public HashAlgorithm HashAlgorithm { get; }

        private byte[] SaltBuffer { get; set; }

        private byte[] InitBuffer { get; set; }

        #endregion

        //################################################################################
        #region Public Members

        public string Encrypt(string plainText, string password)
        {
            var plainTextBuffer = Encoding.UTF8.GetBytes(plainText);
            var encryptedBuffer = EncryptDecryptText(plainTextBuffer, password, true);
            var textEncryptBuffer = new TextEncryptBuffer(password, InitBuffer, SaltBuffer, encryptedBuffer);

            return Convert.ToBase64String(textEncryptBuffer.CombineBuffer());
        }

        public string Decrypt(string encryptedText, string password)
        {
            var encryptedCombinedBuffer = Convert.FromBase64String(encryptedText);
            var textDecryptBuffer = new TextDecryptBuffer(encryptedCombinedBuffer);
            var parsedEncryptedBuffer = textDecryptBuffer.ParseBuffer();

            InitBuffer = textDecryptBuffer.DecryptedInitBuffer;
            SaltBuffer = textDecryptBuffer.DecryptedSaltBuffer;

            var decryptedBuffer = EncryptDecryptText(parsedEncryptedBuffer, password, false);

            return Encoding.UTF8.GetString(decryptedBuffer, 0, decryptedBuffer.Length);
        }

        public string EncryptFile(string sourceFilePath, string password)
        {
            return EncryptDecryptFile(sourceFilePath, password, true);
        }

        public string DecryptFile(string sourceFilePath, string password)
        {
            return EncryptDecryptFile(sourceFilePath, password, false);
        }

        #endregion

        //################################################################################
        #region Private Members

        private string EncryptDecryptFile(string sourceFilePath, string password, bool isEncrypt)
        {
            FileHelper.CheckFileAndSize(sourceFilePath);

            var fileBuffer = FileHelper.ReadFile(sourceFilePath);
            var extension = Path.GetExtension(sourceFilePath);
            byte[] writeBuffer;

            if (isEncrypt)
            {
                var encryptedBuffer = EncryptDecryptText(fileBuffer, password, isEncrypt);
                var fileEncryptBuffer = new FileEncryptBuffer(extension, password, InitBuffer, SaltBuffer, encryptedBuffer);
                writeBuffer = fileEncryptBuffer.CombineBuffer();
            }
            else
            {
                var fileDecryptBuffer = new FileDecryptBuffer(fileBuffer);
                var parsedEncryptedBuffer = fileDecryptBuffer.ParseBuffer();

                InitBuffer = fileDecryptBuffer.DecryptedInitBuffer;
                SaltBuffer = fileDecryptBuffer.DecryptedSaltBuffer;

                writeBuffer = EncryptDecryptText(parsedEncryptedBuffer, password, isEncrypt);
                extension = fileDecryptBuffer.DecryptedExtension;
            }

            return FileHelper.WriteFile(writeBuffer, sourceFilePath, extension, isEncrypt);
        }

        private byte[] EncryptDecryptText(byte[] textBuffer, string password, bool isEncrypt)
        {

            var passwordBuffer = GetPasswordBytes(password);

            using (var rijndael = new RijndaelManaged())
            {
                rijndael.Mode = CipherMode.CBC;

                var cryptoTransform = CreateCryptoTransform(rijndael, passwordBuffer, isEncrypt);

                if (isEncrypt)
                {
                    return EncryptText(cryptoTransform, textBuffer);
                }

                return DecryptText(cryptoTransform, textBuffer);
            }
        }

        private byte[] EncryptText(ICryptoTransform cryptoTransform, byte[] textBuffer)
        {
            using (var memoryStream = new MemoryStream())
            {
                using (var cryptoStream = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Write))
                {
                    WriteCryptoStream(cryptoStream, textBuffer);
                    var encryptedBuffer = memoryStream.ToArray();

                    return encryptedBuffer;
                }
            }
        }

        private byte[] DecryptText(ICryptoTransform cryptoTransform, byte[] textBuffer)
        {
            byte[] decryptBuffer = new byte[textBuffer.Length];
            using (var memoryStream = new MemoryStream(textBuffer))
            {
                using (var cryptoStream = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Read))
                {
                    int readLength = ReadCryptoStream(cryptoStream, decryptBuffer);

                    var decryptedBuffer = new byte[readLength];
                    Buffer.BlockCopy(decryptBuffer, 0, decryptedBuffer, 0, readLength);

                    return decryptedBuffer;
                }
            }
        }

        private void WriteCryptoStream(CryptoStream cryptoStream, byte[] textBuffer)
        {
            cryptoStream.Write(textBuffer, 0, textBuffer.Length);
            cryptoStream.FlushFinalBlock();
        }

        private int ReadCryptoStream(CryptoStream cryptoStream, byte[] decryptBuffer)
        {
            return cryptoStream.Read(decryptBuffer, 0, decryptBuffer.Length);
        }

        private ICryptoTransform CreateCryptoTransform(RijndaelManaged rijndael, byte[] passwordBuffer, bool isEncrypt)
        {
            ICryptoTransform cryptoTransform;

            if (isEncrypt)
            {
                cryptoTransform = rijndael.CreateEncryptor(passwordBuffer, InitBuffer);
            }
            else
            {
                cryptoTransform = rijndael.CreateDecryptor(passwordBuffer, InitBuffer);
            }

            return cryptoTransform;
        }

        private byte[] CreateInitSaltBuffer()
        {
            //Generates a cryptographic random number
            RNGCryptoServiceProvider cryptoServiceProvider = new RNGCryptoServiceProvider();
            var saltBuffer = new byte[Constants.InitSaltLength];
            cryptoServiceProvider.GetBytes(saltBuffer);

            return saltBuffer;
        }

        private byte[] GetPasswordBytes(string password)
        {
            var passwordDeriveBytes = new PasswordDeriveBytes(password, SaltBuffer, GetHashAlgorithm(), 17);
            return passwordDeriveBytes.GetBytes(Constants.KeySize / 8);
        }

        private string GetHashAlgorithm()
        {
            if (HashAlgorithm == HashAlgorithm.SHA256) return "SHA256";
            if (HashAlgorithm == HashAlgorithm.MD5) return "MD5";

            throw new ArgumentException("Invalid hash algorithm.");
        }

        #endregion
    }
}
