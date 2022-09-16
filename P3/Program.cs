using System;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;


namespace P3
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] IV = GetBytes(args[0]);
            int g_e = int.Parse(args[1]),
                g_c = int.Parse(args[2]),
                N_e = int.Parse(args[3]),
                N_c = int.Parse(args[4]),
                x = int.Parse(args[5]);
            byte[] encryptedMessage = GetBytes(args[7]);

            BigInteger g, N, gx, secret1, gy = BigInteger.Parse(args[6]);
            g =  BigInteger.Pow(2, g_e) - g_c;
            N = BigInteger.Pow(2, N_e) - N_c;
            gx = BigInteger.ModPow(g, x,N);
            secret1 = BigInteger.ModPow(gy, x,N);
            byte[] key = secret1.ToByteArray();
            Console.WriteLine(Decrypt(encryptedMessage, key, IV) + "," + Encrypt(args[7], key, IV));
        }
        public static byte[] GetBytes(string str)
        {
            string[] binarystring = str.Split(" ");
            byte[] res = new byte[binarystring.Length];
            int i = 0;
            foreach (var s in binarystring)
            {
                res[i] = Convert.ToByte(s, 16);
                i++;
            }
            return res;
        }
        public static string Decrypt(byte[] text, byte[] key, byte[] IV)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = IV;
                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (MemoryStream memoryStream = new MemoryStream(text))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader streamReader = new StreamReader(cryptoStream))
                        {
                            return streamReader.ReadToEnd();
                        }
                    }
                }
            }
        }
        public static string Encrypt(string text, byte[] key, byte[] IV )
        {
            byte[] array;

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = IV;

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter streamWriter = new StreamWriter(cryptoStream))
                        {
                            streamWriter.Write(text);
                        }

                        array = memoryStream.ToArray();
                    }
                }
            }

            return BitConverter.ToString(array).Replace("-"," ");
        }
    }
}
