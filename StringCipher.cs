using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;

namespace HK.Security
{
    public class StringCipher
    {
        private const string initVector = "lu08veji530t48u2";
        private const string passPhrase = "z2dfc4d738504886890z";
        private const int keysize = 256;

        public static string Encrypt(string plainText)
        {
            try
            {
                byte[] bytes1 = Encoding.UTF8.GetBytes("lu08veji530t48u2");
                byte[] bytes2 = Encoding.UTF8.GetBytes(plainText);
                byte[] bytes3 = new PasswordDeriveBytes("z2dfc4d738504886890z", (byte[])null).GetBytes(32);
                RijndaelManaged rijndaelManaged = new RijndaelManaged();
                rijndaelManaged.Mode = CipherMode.CBC;
                ICryptoTransform encryptor = rijndaelManaged.CreateEncryptor(bytes3, bytes1);
                MemoryStream memoryStream = new MemoryStream();
                CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, encryptor, CryptoStreamMode.Write);
                cryptoStream.Write(bytes2, 0, bytes2.Length);
                cryptoStream.FlushFinalBlock();
                byte[] array = memoryStream.ToArray();
                memoryStream.Close();
                cryptoStream.Close();
                return Convert.ToBase64String(array);
            }
            catch
            {
                return (string)null;
            }
        }

        public static string Decrypt(string cipherText)
        {
            try
            {
                byte[] bytes1 = Encoding.ASCII.GetBytes("lu08veji530t48u2");
                byte[] buffer = Convert.FromBase64String(cipherText);
                byte[] bytes2 = new PasswordDeriveBytes("z2dfc4d738504886890z", (byte[])null).GetBytes(32);
                RijndaelManaged rijndaelManaged = new RijndaelManaged();
                rijndaelManaged.Mode = CipherMode.CBC;
                ICryptoTransform decryptor = rijndaelManaged.CreateDecryptor(bytes2, bytes1);
                MemoryStream memoryStream = new MemoryStream(buffer);
                CryptoStream cryptoStream = new CryptoStream((Stream)memoryStream, decryptor, CryptoStreamMode.Read);
                byte[] numArray = new byte[buffer.Length];
                int count = cryptoStream.Read(numArray, 0, numArray.Length);
                memoryStream.Close();
                cryptoStream.Close();
                return Encoding.UTF8.GetString(numArray, 0, count);
            }
            catch
            {
                return (string)null;
            }
        }
    }
}
