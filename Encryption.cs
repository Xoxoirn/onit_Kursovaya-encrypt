using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Kursovaya_ONIT_1
{
    public class Encryption
    {
        public string SourceFilePath { get; set; }
        public string FormatFile { get; set; }
        public string Key { set { changeKey(value); } }
        /// <summary>
        /// TRUE - DES
        /// FALSE - AES
        /// </summary>
        public bool UseDES { get; set; }

        public bool DeleteSource { get; set; }

        private byte[] _keyAES;
        private byte[] _keyDES;

        public string GetNameFileWithoutFormat()
        {
            var tmp = SourceFilePath.Split('\\');
            var name = tmp[tmp.Length - 1].Remove(tmp[tmp.Length - 1].LastIndexOf('.'));
            return name;
        }

        public Encryption(string path, string key, bool DES = false)
        {
            SourceFilePath = path;
            string[] tmp = path.Split('.');
            FormatFile = tmp[tmp.Length - 1];
            Key = key;
            UseDES = DES;
            DeleteSource = false;
        }
        public async Task<string> EncryptInFileAsync(string newFilePath)
        {
            return await Task.Run(() =>
            {
                byte[] encByte;
                if (UseDES)
                {
                    encByte = encryptDES();
                }
                else
                {
                    encByte = encryptAES();
                }
                File.WriteAllBytes(newFilePath, encByte);
                if(DeleteSource)
                {
                    File.Delete(SourceFilePath);
                }
                return newFilePath;
            });
        }
        public async Task<string> DecryptInFileAsync(string newFilePath)
        {
            return await Task.Run(() =>
            {
                byte[] encByte;
                if (UseDES)
                {
                    encByte = decryptDES();
                }
                else
                {
                    encByte = decryptAES();
                }
                File.WriteAllBytes(newFilePath, encByte);
                File.Delete(SourceFilePath);
                return newFilePath;
            });
        }

        private void changeKey(string newKey)
        {
            SHA256 m = new SHA256CryptoServiceProvider();
            _keyAES = m.ComputeHash(Encoding.ASCII.GetBytes(newKey));
            generateKeyForDES();
        }
        private void generateKeyForDES()
        {
            _keyDES = new byte[8];
            for(int i = 0; i < 8; i++)
            {
                _keyDES[i] = (byte)(_keyAES[i * 4] ^ _keyAES[i * 4 + 1] ^ _keyAES[i * 4 + 2] ^ _keyAES[i * 4 + 3]);
            }
        }

        private byte[] encryptDES()
        {
            try
            {
                byte[] encrypted;
                byte[] IV;

                using (DES DESAlg = DES.Create())
                {
                    DESAlg.Mode = CipherMode.CFB;

                    DESAlg.Key = _keyDES;

                    DESAlg.GenerateIV();
                    IV = DESAlg.IV;
                    DESAlg.Padding = PaddingMode.PKCS7;

                    var encryptor = DESAlg.CreateEncryptor(DESAlg.Key, DESAlg.IV);

                    // Create the streams used for encryption. 
                    using (var msEncrypt = new MemoryStream())
                    {
                        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            byte[] fileBytes = File.ReadAllBytes(SourceFilePath);
                            csEncrypt.Write(fileBytes, 0, fileBytes.Length);
                            csEncrypt.FlushFinalBlock();
                            encrypted = msEncrypt.ToArray();
                        }
                    }
                }

                var combinedIvCt = new byte[IV.Length + encrypted.Length];
                Array.Copy(IV, 0, combinedIvCt, 0, IV.Length);
                Array.Copy(encrypted, 0, combinedIvCt, IV.Length, encrypted.Length);

                return combinedIvCt;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        private byte[] decryptDES()
        {
            try
            {
                byte[] buff;

                byte[] cipherTextCombined;
                cipherTextCombined = File.ReadAllBytes(SourceFilePath);

                using (DES DESAlg = DES.Create())
                {
                    DESAlg.Mode = CipherMode.CFB;
                    DESAlg.Key = _keyDES;

                    byte[] IV = new byte[DESAlg.BlockSize / 8];
                    byte[] cipherText = new byte[cipherTextCombined.Length - IV.Length];

                    Array.Copy(cipherTextCombined, IV, IV.Length);
                    Array.Copy(cipherTextCombined, IV.Length, cipherText, 0, cipherText.Length);

                    DESAlg.IV = IV;
                    DESAlg.Padding = PaddingMode.PKCS7;

                    // Create a decrytor to perform the stream transform.
                    ICryptoTransform decryptor = DESAlg.CreateDecryptor(DESAlg.Key, DESAlg.IV);

                    // Create the streams used for decryption. 
                    using (var msDecrypt = new MemoryStream(cipherText))
                    {
                        using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            buff = new byte[cipherText.Length];
                            csDecrypt.Read(buff, 0, buff.Length);
                        }
                    }
                }
                return buff;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        private byte[] encryptAES()
        {
            try
            {
                byte[] encrypted;
                byte[] IV;

                using (Aes aesAlg = Aes.Create())
                {
                    aesAlg.Mode = CipherMode.CFB;

                    aesAlg.Key = _keyAES;

                    aesAlg.GenerateIV();
                    IV = aesAlg.IV;
                    aesAlg.Padding = PaddingMode.PKCS7;

                    var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                    // Create the streams used for encryption. 
                    using (var msEncrypt = new MemoryStream())
                    {
                        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            byte[] fileBytes = File.ReadAllBytes(SourceFilePath);
                            csEncrypt.Write(fileBytes, 0, fileBytes.Length);
                            csEncrypt.FlushFinalBlock();
                            encrypted = msEncrypt.ToArray();
                        }
                    }
                }

                var combinedIvCt = new byte[IV.Length + encrypted.Length];
                Array.Copy(IV, 0, combinedIvCt, 0, IV.Length);
                Array.Copy(encrypted, 0, combinedIvCt, IV.Length, encrypted.Length);

                return combinedIvCt;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        private byte[] decryptAES()
        {
            try
            {
                byte[] buff;

                byte[] cipherTextCombined;
                cipherTextCombined = File.ReadAllBytes(SourceFilePath);

                using (Aes aesAlg = Aes.Create())
                {
                    aesAlg.Mode = CipherMode.CFB;

                    aesAlg.Key = _keyAES;

                    byte[] IV = new byte[aesAlg.BlockSize / 8];
                    byte[] cipherText = new byte[cipherTextCombined.Length - IV.Length];

                    Array.Copy(cipherTextCombined, IV, IV.Length);
                    Array.Copy(cipherTextCombined, IV.Length, cipherText, 0, cipherText.Length);

                    aesAlg.IV = IV;
                    aesAlg.Padding = PaddingMode.PKCS7;

                    // Create a decrytor to perform the stream transform.
                    ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                    // Create the streams used for decryption. 
                    using (var msDecrypt = new MemoryStream(cipherText))
                    {
                        using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            buff = new byte[cipherText.Length];
                            csDecrypt.Read(buff, 0, buff.Length);
                        }
                    }
                }
                return buff;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
    }
}
