using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace KriptografiK
{
    internal class Program
    {
        // AES Şifreleme ve Çözme
        public static string EncryptAES(string sifre1, string key1)
        {
            byte[] iv = new byte[16]; // Rastgele IV üretebiliriz
            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key1);
                aes.GenerateIV();  // Rastgele IV üretildi
                aes.IV = aes.IV;

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter streamWriter = new StreamWriter(cryptoStream))
                        {
                            streamWriter.Write(sifre1);
                        }
                        byte[] encryptedData = memoryStream.ToArray();
                        // IV'yi şifreli metinle birlikte döndürüyoruz
                        byte[] result = new byte[encryptedData.Length + aes.IV.Length];
                        Array.Copy(aes.IV, 0, result, 0, aes.IV.Length);
                        Array.Copy(encryptedData, 0, result, aes.IV.Length, encryptedData.Length);
                        return Convert.ToBase64String(result);
                    }
                }
            }
        }

        public static string DecryptAES(string c1, string key1)
        {
            byte[] buffer = Convert.FromBase64String(c1);
            byte[] iv = new byte[16];
            Array.Copy(buffer, 0, iv, 0, iv.Length);  // IV'yi ayırıyoruz
            byte[] cipherText = new byte[buffer.Length - iv.Length];
            Array.Copy(buffer, iv.Length, cipherText, 0, cipherText.Length);  // Şifreli veriyi ayırıyoruz

            using (Aes aes = Aes.Create())
            {
                aes.Key = Encoding.UTF8.GetBytes(key1);
                aes.IV = iv; // IV'yi belirliyoruz

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (MemoryStream memoryStream = new MemoryStream(cipherText))
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

        // RSA Şifreleme
        public static string EncryptRSA(string sifre2, string publicKey)
        {
            using (RSA rsa = RSA.Create())
            {
                rsa.FromXmlString(publicKey);
                byte[] dataToEncrypt = Encoding.UTF8.GetBytes(sifre2);
                byte[] encryptedData = rsa.Encrypt(dataToEncrypt, RSAEncryptionPadding.Pkcs1);
                return Convert.ToBase64String(encryptedData);
            }
        }

        // DES Şifreleme
        public static string EncryptDES(string sifre3, string key3)
        {
            using (DESCryptoServiceProvider des = new DESCryptoServiceProvider())
            {
                des.Key = Encoding.UTF8.GetBytes(key3);
                des.IV = Encoding.UTF8.GetBytes(key3);

                byte[] plaintextBytes = Encoding.UTF8.GetBytes(sifre3);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(plaintextBytes, 0, plaintextBytes.Length);
                        cs.FlushFinalBlock();
                        return Convert.ToBase64String(ms.ToArray());
                    }
                }
            }
        }
        //BLOWFİSH
        public static string Encrypt(string plaintext, string key)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] inputBytes = Encoding.UTF8.GetBytes(plaintext);

            BlowfishCipher cipher = new BlowfishCipher();
            cipher.Init(true, new KeyParameter(keyBytes));

            byte[] outputBytes = new byte[inputBytes.Length];
            int blockSize = cipher.GetBlockSize();

            for (int i = 0; i < inputBytes.Length; i += blockSize)
            {
                cipher.ProcessBlock(inputBytes, i, outputBytes, i);
            }

            return Convert.ToBase64String(outputBytes);
        }

        public static string Decrypt(string encryptedText, string key)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            byte[] inputBytes = Convert.FromBase64String(encryptedText);

            BlowfishCipher cipher = new BlowfishCipher();
            cipher.Init(false, new KeyParameter(keyBytes));

            byte[] outputBytes = new byte[inputBytes.Length];
            int blockSize = cipher.GetBlockSize();

            for (int i = 0; i < inputBytes.Length; i += blockSize)
            {
                cipher.ProcessBlock(inputBytes, i, outputBytes, i);
            }

            return Encoding.UTF8.GetString(outputBytes).TrimEnd('\0');
        }
        public static string DecryptDES(string c3, string key3)
        {
            using (DESCryptoServiceProvider des = new DESCryptoServiceProvider())
            {
                des.Key = Encoding.UTF8.GetBytes(key3);
                des.IV = Encoding.UTF8.GetBytes(key3);

                byte[] cipherBytes = Convert.FromBase64String(c3);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, des.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(cipherBytes, 0, cipherBytes.Length);
                        cs.FlushFinalBlock();
                        return Encoding.UTF8.GetString(ms.ToArray());
                    }
                }
            }
        }

        // DES3 Şifreleme
        private static byte[] des3Key;
        private static byte[] des3IV;
        public static byte[] EncryptDES3(string plainText)
        {
            using (TripleDESCryptoServiceProvider tripleDES = new TripleDESCryptoServiceProvider())
            {
                // Key ve IV'yi otomatik olarak oluşturuyoruz
                des3Key = tripleDES.Key;
                des3IV = tripleDES.IV;

                ICryptoTransform encryptor = tripleDES.CreateEncryptor(des3Key, des3IV);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        byte[] inputBytes = Encoding.UTF8.GetBytes(plainText);
                        cs.Write(inputBytes, 0, inputBytes.Length);
                        cs.FlushFinalBlock();
                        return ms.ToArray();
                    }
                }
            }
        }

        static void Main(string[] args)
        {
            Console.WriteLine("-------------- ERAY AŞİNA --------------");
            Console.WriteLine("1-OLUŞTUR");
            Console.WriteLine("2-ÇÖZ");
            int secim = Convert.ToInt32(Console.ReadLine());
            string keyAES = "1234567890123456";
            string keyDES = "ABCDEFGH";

            if (secim == 1)
            {
                Console.WriteLine("Şifreleme yöntemi seçin:");
                Console.WriteLine("1-AES");
                Console.WriteLine("2-RSA");
                Console.WriteLine("3-DES");
                Console.WriteLine("4-DES3");
                //Console.WriteLine("5-BLOWFİSH");
                int ssec = Convert.ToInt32(Console.ReadLine());

                if (ssec == 1) // AES
                {
                    Console.WriteLine("-------------- AES --------------");
                    Console.Write("Şifreyi Giriniz: ");
                    string sifre = Console.ReadLine();
                    string encryptedText = EncryptAES(sifre, keyAES);
                    Console.WriteLine("Şifrelenmiş Hali: " + encryptedText);
                }
                else if (ssec == 2) // RSA
                {
                    Console.WriteLine("-------------- RSA --------------");
                    using (RSA rsa = RSA.Create())
                    {
                        string publicKey = rsa.ToXmlString(false); // Genel anahtar
                        Console.Write("Şifreyi Giriniz: ");
                        string sifre = Console.ReadLine();
                        string encryptedText = EncryptRSA(sifre, publicKey);
                        Console.WriteLine("Şifrelenmiş Hali: " + encryptedText);
                    }
                }
                else if (ssec == 3) // DES
                {
                    Console.WriteLine("-------------- DES --------------");
                    Console.Write("Şifreyi Giriniz: ");
                    string sifre = Console.ReadLine();
                    string encryptedText = EncryptDES(sifre, keyDES);
                    Console.WriteLine("Şifrelenmiş Hali: " + encryptedText);
                }
                else if (ssec == 4) // DES3
                {
                    Console.WriteLine("-------------- DES3 --------------");
                    Console.Write("Şifreyi Giriniz: ");
                    string sifre = Console.ReadLine();
                    byte[] encryptedData = EncryptDES3(sifre);
                    string encryptedText = Convert.ToBase64String(encryptedData);
                    Console.WriteLine("Şifrelenmiş Hali: " + encryptedText);
                }
                //else if (ssec==5)
                //{
                //    Console.WriteLine("-------------- BLOWFİSH --------------");
                //    string keyB = "supersecretkey";
                //    Console.Write("Şifre Giriniz: ");
                //    string sifre=Console.ReadLine();
                //    string encryptedText = Encrypt(sifre, keyB);
                //    Console.WriteLine($"Şifrelenmiş Hali: {encryptedText}");
                //}
            }
            else if (secim == 2) // Çözme
            {
                Console.WriteLine("Şifreyi çözme yöntemi seçin:");
                Console.WriteLine("1-AES");
                Console.WriteLine("3-DES");
                int ssec = Convert.ToInt32(Console.ReadLine());

                if (ssec == 1) // AES
                {
                    Console.WriteLine("-------------- AES --------------");
                    Console.Write("Şifreyi Giriniz: ");
                    string encryptedText = Console.ReadLine();
                    string decryptedText = DecryptAES(encryptedText, keyAES);
                    Console.WriteLine("Çözülmüş Hali: " + decryptedText);
                }
                //else if (ssec == 2) // RSA
                //{
                //    Console.WriteLine("-------------- RSA --------------");
                //    Console.Write("Şifreyi Giriniz: ");
                //    string encryptedText = Console.ReadLine();
                //    // RSA private key ile çözme eklenmeli
                //    Console.WriteLine("RSA özel anahtarınız eksik.");
                //}
                else if (ssec == 3) // DES
                {
                    Console.WriteLine("-------------- DES --------------");
                    Console.Write("Şifreyi Giriniz: ");
                    string encryptedText = Console.ReadLine();
                    string decryptedText = DecryptDES(encryptedText, keyDES);
                    Console.WriteLine("Çözülmüş Hali: " + decryptedText);
                }
                //else if (ssec == 4) // DES3
                //{
                    
                //}
            }
            Console.ReadKey();
        }
    }
}
