using System;
using System.IO;

namespace TextEncryptDecrypt
{
    internal class FileHelper
    {
        //################################################################################
        #region Constructor

        private FileHelper()
        {

        }

        #endregion

        //################################################################################
        #region Internal Static Members

        internal static byte[] ReadFile(string filePath)
        {
            byte[] fileBuffer;

            using (var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            {
                var fileLength = (int)fileStream.Length;
                fileBuffer = new byte[fileLength];

                fileStream.Read(fileBuffer, 0, fileLength);
                fileStream.Close();
            }

            return fileBuffer;
        }

        internal static string WriteFile(byte[] byteBuffer, string sourceFilePath, string extension, bool isEncrypt)
        {
            var targetFilePath = CreateTargetFile(sourceFilePath, extension, isEncrypt);

            using (var fileStream = new FileStream(targetFilePath, FileMode.Open, FileAccess.Write))
            {
                fileStream.Write(byteBuffer, 0, byteBuffer.Length);
                fileStream.Close();
            }

            return targetFilePath;
        }

        internal static void CheckFileAndSize(string filePath)
        {
            CheckFile(filePath);

            var isFileTooBig = false;
            using (var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            {
                if (fileStream.Length > Constants.MaxFileSize)
                {
                    isFileTooBig = true;
                }

                fileStream.Close();
            }

            if (isFileTooBig)
            {
                throw new ArgumentException("File size cannot be large than 5 MB.");
            }
        }

        internal static void CheckFile(string filePath)
        {
            if (!File.Exists(filePath))
            {
                throw new ArgumentException($"Path: {filePath} doesn't exists.");
            }
        }

        #endregion

        //################################################################################
        #region Private Static Members

        private static string CreateTargetFile(string sourceFilePath, string extension, bool isEncrypt)
        {
            var sourceFileDirectory = Path.GetDirectoryName(sourceFilePath);
            var sourceFileName = Path.GetFileNameWithoutExtension(sourceFilePath);

            var targetFilePath = isEncrypt ? $"{sourceFileDirectory}\\{sourceFileName}.encrypt" :
                                             $"{sourceFileDirectory}\\{sourceFileName}-decrypted{extension}";

            if (!File.Exists(targetFilePath))
            {
                using (var fileStream = File.Create(targetFilePath))
                {
                    fileStream.Close();
                }
            }

            return targetFilePath;
        }

        #endregion
    }
}
