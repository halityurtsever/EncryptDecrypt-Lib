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

        internal static void WriteFile(byte[] byteBuffer, string targetFile)
        {
            using (var fileStream = new FileStream(targetFile, FileMode.Open, FileAccess.Write))
            {
                fileStream.Write(byteBuffer, 0, byteBuffer.Length);
                fileStream.Close();
            }
        }

        internal static string CreateTargetFile(string fileFolder, string fileName, string fileExtension, bool isEncrypt)
        {
            var targetFilePath = isEncrypt ? $"{fileFolder}\\{fileName}.encrypt" :
                                             $"{fileFolder}\\{fileName}-decrypted{fileExtension}";

            if (!File.Exists(targetFilePath))
            {
                using (var fileStream = File.Create(targetFilePath))
                {
                    fileStream.Close();
                }
            }

            return targetFilePath;
        }

        internal static void CheckFile(string filePath)
        {
            CheckFileExistence(filePath);
            CheckFileSize(filePath);
        }

        internal static void CheckFolder(string folderPath)
        {
            if (!Directory.Exists(folderPath))
            {
                throw new ArgumentException($"Invalid folder path: {folderPath}");
            }
        }

        #endregion

        //################################################################################
        #region Private Static Members

        private static void CheckFileExistence(string filePath)
        {
            if (!File.Exists(filePath))
            {
                throw new ArgumentException($"Path: {filePath} doesn't exists.");
            }
        }

        private static void CheckFileSize(string filePath)
        {
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

        #endregion
    }
}
