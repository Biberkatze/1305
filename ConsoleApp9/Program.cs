using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("Willkommen zur Verschlüsselungs-App!");
        Console.Write("Geben Sie den Pfad zur Datei ein: ");
        string filePath = Console.ReadLine();

        Console.WriteLine("Wählen Sie die Verschlüsselungsmethode:");
        Console.WriteLine("1. AES");
        Console.WriteLine("2. RSA");
        Console.WriteLine("3. DES");
        string choice = Console.ReadLine();

        Console.WriteLine("Wählen Sie die Operation:");
        Console.WriteLine("1. Verschlüsseln");
        Console.WriteLine("2. Entschlüsseln");
        string operation = Console.ReadLine();

        switch (choice)
        {
            case "1":
                AESOperation(filePath, operation == "1");
                break;
            case "2":
                RSAOperation(filePath, operation == "1");
                break;
            case "3":
                DESOperation(filePath, operation == "1");
                break;
            default:
                Console.WriteLine("Ungültige Auswahl!");
                break;
        }
    }

    static void AESOperation(string filePath, bool encrypt)
    {
        byte[] key = Encoding.UTF8.GetBytes("1234567890123456");
        byte[] iv = Encoding.UTF8.GetBytes("1234567890123456");

        if (encrypt)
        {
            byte[] encrypted = EncryptFileAES(File.ReadAllBytes(filePath), key, iv);
            File.WriteAllBytes(filePath + ".aes", encrypted);
            Console.WriteLine("Datei erfolgreich verschlüsselt: " + filePath + ".aes");
        }
        else
        {
            byte[] decrypted = DecryptFileAES(File.ReadAllBytes(filePath), key, iv);
            File.WriteAllBytes(filePath.Replace(".aes", ""), decrypted);
            Console.WriteLine("Datei erfolgreich entschlüsselt: " + filePath.Replace(".aes", ""));
        }
    }

    static byte[] EncryptFileAES(byte[] data, byte[] key, byte[] iv)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            aes.IV = iv;
            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(data, 0, data.Length);
                }
                return ms.ToArray();
            }
        }
    }

    static byte[] DecryptFileAES(byte[] data, byte[] key, byte[] iv)
    {
        using (Aes aes = Aes.Create())
        {
            aes.Key = key;
            aes.IV = iv;
            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(data, 0, data.Length);
                }
                return ms.ToArray();
            }
        }
    }

    static void RSAOperation(string filePath, bool encrypt)
    {
        using (RSA rsa = RSA.Create())
        {
            rsa.KeySize = 2048;
            string keyPath = "rsa_key.xml";
            if (encrypt)
            {
                File.WriteAllText(keyPath, rsa.ToXmlString(true));
                byte[] encrypted = EncryptFileRSA(File.ReadAllBytes(filePath), rsa.ExportParameters(false));
                File.WriteAllBytes(filePath + ".rsa", encrypted);
                Console.WriteLine("Datei erfolgreich verschlüsselt: " + filePath + ".rsa");
            }
            else
            {
                rsa.FromXmlString(File.ReadAllText(keyPath));
                byte[] decrypted = DecryptFileRSA(File.ReadAllBytes(filePath), rsa.ExportParameters(true));
                File.WriteAllBytes(filePath.Replace(".rsa", ""), decrypted);
                Console.WriteLine("Datei erfolgreich entschlüsselt: " + filePath.Replace(".rsa", ""));
            }
        }
    }

    static byte[] EncryptFileRSA(byte[] data, RSAParameters rsaKey)
    {
        using (RSA rsa = RSA.Create())
        {
            rsa.ImportParameters(rsaKey);
            int maxLength = (rsa.KeySize / 8) - 42; // PKCS1 padding
            using (MemoryStream ms = new MemoryStream())
            {
                for (int i = 0; i < data.Length; i += maxLength)
                {
                    byte[] chunkData = data[i..Math.Min(i + maxLength, data.Length)];
                    byte[] encryptedChunk = rsa.Encrypt(chunkData, RSAEncryptionPadding.Pkcs1);
                    ms.Write(encryptedChunk, 0, encryptedChunk.Length);
                }
                return ms.ToArray();
            }
        }
    }

    static byte[] DecryptFileRSA(byte[] data, RSAParameters rsaKey)
    {
        using (RSA rsa = RSA.Create())
        {
            rsa.ImportParameters(rsaKey);
            int chunkSize = rsa.KeySize / 8; // The size of RSA key in bytes
            using (MemoryStream ms = new MemoryStream())
            {
                for (int i = 0; i < data.Length; i += chunkSize)
                {
                    byte[] chunkData = data[i..Math.Min(i + chunkSize, data.Length)];
                    byte[] decryptedChunk = rsa.Decrypt(chunkData, RSAEncryptionPadding.Pkcs1);
                    ms.Write(decryptedChunk, 0, decryptedChunk.Length);
                }
                return ms.ToArray();
            }
        }
    }

    static void DESOperation(string filePath, bool encrypt)
    {
        byte[] key = Encoding.UTF8.GetBytes("12345678");
        byte[] iv = Encoding.UTF8.GetBytes("12345678");

        if (encrypt)
        {
            byte[] encrypted = EncryptFileDES(File.ReadAllBytes(filePath), key, iv);
            File.WriteAllBytes(filePath + ".des", encrypted);
            Console.WriteLine("Datei erfolgreich verschlüsselt: " + filePath + ".des");
        }
        else
        {
            byte[] decrypted = DecryptFileDES(File.ReadAllBytes(filePath), key, iv);
            File.WriteAllBytes(filePath.Replace(".des", ""), decrypted);
            Console.WriteLine("Datei erfolgreich entschlüsselt: " + filePath.Replace(".des", ""));
        }
    }

    static byte[] EncryptFileDES(byte[] data, byte[] key, byte[] iv)
    {
        using (DES des = DES.Create())
        {
            des.Key = key;
            des.IV = iv;
            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, des.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(data, 0, data.Length);
                }
                return ms.ToArray();
            }
        }
    }

    static byte[] DecryptFileDES(byte[] data, byte[] key, byte[] iv)
    {
        using (DES des = DES.Create())
        {
            des.Key = key;
            des.IV = iv;
            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, des.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(data, 0, data.Length);
                }
                return ms.ToArray();
            }
        }
    }
}
