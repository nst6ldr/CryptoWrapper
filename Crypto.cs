using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.Management;


namespace Cryptography
{
    /// <summary>
    /// Provides standardized cryptographic functions in a wrapper. Use this for encryption, decryption and hashing strings.
    /// </summary>
    class Strings
    {
        int GenericOffset = 0;

        /// <summary>
        /// The public key used by all crypto functions performed with this instance. Has to be 16 characters long, will automatically be padded if less and trimmed if more.
        /// </summary>
        public string public_key { get; set; }
        
        /// <summary>
        /// Returns a system unique GUID based on CPU, HDD and Motherboard.
        /// </summary>
        /// <returns></returns>
        public string GetSystemGUID()
        {
            string GUID = "N/A";
            var mbs = new ManagementObjectSearcher("Select ProcessorId From Win32_processor");
            ManagementObjectCollection mbsList = mbs.Get();
            foreach (ManagementObject mo in mbsList)
            {
                GUID = mo["ProcessorId"].ToString();
                break;
            }

            ManagementObject dsk = new ManagementObject(@"win32_logicaldisk.deviceid=""c:""");
            dsk.Get();
            GUID = GUID + dsk["VolumeSerialNumber"].ToString();

            ManagementObjectSearcher mos = new ManagementObjectSearcher("SELECT * FROM Win32_BaseBoard");
            ManagementObjectCollection moc = mos.Get();
            foreach (ManagementObject mo in moc)
            {
                GUID = GUID + mo["SerialNumber"].ToString();
            }
            return GUID;
        }

        /// <summary>
        /// All required parameters for cryptographic functions.
        /// </summary>
        /// <param name="pkey">Public/Symmetric key used for encryption and decryption.</param>
        public Strings(string pkey = null)
        {
            public_key = pkey;
        }

        /// <summary>
        /// The SHA2 hash algorithm, returns the hashed string.
        /// </summary>
        /// <param name="input">The string to hash.</param>
        /// <param name="salt">The salt to hash the string with.</param>
        /// <returns></returns>
        public string SHA2(string input, string salt)
        {
            input = input + salt;
            byte[] bytes = Encoding.UTF8.GetBytes(input);
            SHA256Managed hashstring = new SHA256Managed();
            byte[] bhash = hashstring.ComputeHash(bytes);
            string Hash = string.Empty;
            foreach (byte x in bhash)
            {
                Hash += String.Format("{0:x2}", x);
            }
            return Hash;
        }
        
        /// <summary>
        /// Encryption of a string with AES-256-CBC, the initialisation vector is prefixed to the ciphertext.
        /// </summary>
        /// <param name="input">The string to encrypt.</param>
        /// <returns></returns>
        public string Encrypt(string input)
        {
            string cipher = null;

            RijndaelManaged Crypto = new RijndaelManaged();
            Random r = new Random((Convert.ToInt32(System.DateTime.Now.Millisecond)) + GenericOffset++);

            Crypto.KeySize = 256;
            Crypto.BlockSize = 128;
            Crypto.Mode = CipherMode.CBC;
            Crypto.Padding = PaddingMode.PKCS7;

            byte[] message = Encoding.UTF8.GetBytes(@input);
            byte[] pubkey = Encoding.UTF8.GetBytes(@public_key.PadRight(16, '#').Substring(0, 16));
            byte[] iv = new byte[16];

            r.NextBytes(iv);

            Crypto.Key = pubkey;
            Crypto.IV = iv; 
            
            try
            {
                ICryptoTransform Encrypt = Crypto.CreateEncryptor();
                cipher = @Convert.ToBase64String(iv) + @Convert.ToBase64String(Encrypt.TransformFinalBlock(message, 0, message.Length));
            }
            catch (CryptographicException e)
            {
                cipher = "ENCRYPTION ERROR" + e;
            }
            return cipher;
        }

        /// <summary>
        /// Decryption of a string with AES-256-CBC, the initialisation vector is derived from the encrypted string.
        /// </summary>
        /// <param name="input">The string to decrypt.</param>
        /// <returns></returns>
        public string Decrypt(string input)
        {
            string message = "";
            RijndaelManaged Crypto = new RijndaelManaged();

            Crypto.KeySize = 256;
            Crypto.BlockSize = 128;
            Crypto.Mode = CipherMode.CBC;
            Crypto.Padding = PaddingMode.PKCS7;

            byte[] iv = Convert.FromBase64String(@input.Substring(0, 24));
            byte[] cipherdata = Convert.FromBase64String(@input.Substring(24, input.Length - 24));
            byte[] pubkey = Encoding.UTF8.GetBytes(@public_key.PadRight(16, '#').Substring(0, 16));
            
            Crypto.Key = pubkey;
            Crypto.IV = iv;

            try
            {
                ICryptoTransform Decrypt = Crypto.CreateDecryptor();
                message = Encoding.UTF8.GetString(Decrypt.TransformFinalBlock(cipherdata, 0, cipherdata.Length));
            }
            catch (CryptographicException e)
            {
                message = "DECRYPTION ERROR" + e;
            }
            return message;
        }
    }
}