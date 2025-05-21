// ===============================================================================
// Arix Encryptor v1.0
// Author       : Ari Sohandri Putra
// Build Date   : 05/20/2025
// ===============================================================================
// Description:
// Arix Encryptor is a secure file encryption and decryption tool written in C#
// (compatible with .NET Framework 2.0). This class provides functionality to encrypt
// and decrypt files using AES (Rijndael) in CBC mode with PBKDF2 for key derivation,
// and HMAC-SHA256 for integrity verification.
//
// Key Features:
// - Adds a unique file header to identify encrypted files.
// - Encrypts original file content and stores original file extension.
// - Uses a secure key derivation function (PBKDF2) with custom salt and iterations.
// - Verifies decrypted content integrity with a stored HMAC hash.
// - Designed with multithreading support and event-based progress feedback.
// ===============================================================================

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
namespace ArixEncryptor
{
    public class Encryptor
    {
        // Enhanced security constants
        private const int SaltSize = 32; // bytes
        private const int KeySize = 32; // 256 bits
        private const int IvSize = 16; // 128 bits
        private const int HmacSize = 32; // 256 bits (SHA256)
        private const int Iterations = 5000; // Increased PBKDF2 iterations
        private const string MagicHeader = "GaRuDaxEnc"; // Custom file header to identify encrypted files

        // Event for progress reporting
        public event ProgressChangedEventHandler ProgressChanged;
        public event OperationCompletedEventHandler OperationCompleted;

        // Thread-safe random number generator
        private static RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
        private static object rngLock = new object();

        // Delegate for events
        public delegate void ProgressChangedEventHandler(int progress);
        public delegate void OperationCompletedEventHandler(bool success, string message);

        // Check if file is already encrypted
        public bool IsFileEncrypted(string filePath)
        {
            try
            {
                if (!File.Exists(filePath)) return false;

                // Read the first few bytes to check for our magic header
                using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                {
                    // Our encrypted files start with the magic header followed by extension length
                    byte[] headerBytes = new byte[MagicHeader.Length];
                    fs.Read(headerBytes, 0, headerBytes.Length);
                    string header = Encoding.ASCII.GetString(headerBytes);

                    return header == MagicHeader;
                }
            }
            catch
            {
                return false;
            }
        }

        // Encrypt file (original file -> .enc)
        public void EncryptFile(string filePath, string password, bool makeBackup = false)
        {
            Thread worker = new Thread(delegate()
            {
                try
                {
                    // Validate inputs
                    if (!File.Exists(filePath))
                    {
                        if (OperationCompleted != null)
                            OperationCompleted(false, "File not found.");
                        return;
                    }

                    // Check if file is already encrypted
                    if (IsFileEncrypted(filePath))
                    {
                        if (OperationCompleted != null)
                            OperationCompleted(false, "File is already encrypted.");
                        return;
                    }

                    // Create backup if requested
                    if (makeBackup)
                    {
                        BackupFile(filePath);
                    }

                    // Generate cryptographic elements
                    byte[] salt = GenerateRandomBytes(SaltSize);
                    byte[] iv = GenerateRandomBytes(IvSize);

                    // Initialize key variables before passing by reference
                    byte[] key = null;
                    byte[] hmacKey = null;
                    DeriveKeys(password, salt, out key, out hmacKey);

                    // Get file extension
                    string ext = Path.GetExtension(filePath);
                    byte[] extBytes = Encoding.UTF8.GetBytes(ext);
                    byte extLen = (byte)extBytes.Length;

                    // Temporary output file
                    string tempFile = filePath + ".tmp";

                    // First pass - calculate HMAC of plaintext
                    byte[] plaintextHash;
                    using (HMACSHA256 hmac = new HMACSHA256(hmacKey))
                    {
                        using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                        {
                            plaintextHash = hmac.ComputeHash(fs);
                        }
                    }

                    // Encrypt the file
                    using (FileStream fsInput = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                    using (FileStream fsOutput = new FileStream(tempFile, FileMode.Create))
                    {
                        // Write magic header + extension info + salt + IV + plaintext hash
                        byte[] headerBytes = Encoding.ASCII.GetBytes(MagicHeader);
                        fsOutput.Write(headerBytes, 0, headerBytes.Length);
                        fsOutput.WriteByte(extLen);
                        fsOutput.Write(extBytes, 0, extBytes.Length);
                        fsOutput.Write(salt, 0, salt.Length);
                        fsOutput.Write(iv, 0, iv.Length);
                        fsOutput.Write(plaintextHash, 0, plaintextHash.Length);

                        // Encrypt the file content
                        using (RijndaelManaged aes = new RijndaelManaged())
                        {
                            aes.KeySize = 256;
                            aes.BlockSize = 128;
                            aes.Mode = CipherMode.CBC;
                            aes.Padding = PaddingMode.PKCS7;

                            using (CryptoStream cryptoStream = new CryptoStream(fsOutput, aes.CreateEncryptor(key, iv), CryptoStreamMode.Write))
                            {
                                CopyStreamWithProgress(fsInput, cryptoStream, fsInput.Length);
                                cryptoStream.FlushFinalBlock();
                            }
                        }
                    }

                    // Replace original file with encrypted version (.enc)
                    File.Delete(filePath);
                    File.Move(tempFile, Path.ChangeExtension(filePath, ".enc"));

                    LogActivity("ENCRYPT_SUCCESS", filePath);
                    if (OperationCompleted != null)
                        OperationCompleted(true, "File encrypted successfully.");
                }
                catch (ThreadAbortException)
                {
                    // Clean up if operation was aborted
                    if (File.Exists(filePath + ".tmp")) File.Delete(filePath + ".tmp");
                    LogActivity("ENCRYPT_ABORTED", filePath);
                    if (OperationCompleted != null)
                        OperationCompleted(false, "Encryption was aborted.");
                }
                catch (Exception ex)
                {
                    LogActivity("ENCRYPT_FAILED: " + ex.Message, filePath);
                    if (OperationCompleted != null)
                        OperationCompleted(false, "Encryption failed: " + ex.Message);
                }
            });

            worker.IsBackground = true;
            worker.Start();
        }

        // Decrypt file (.enc -> original file)
        public void DecryptFile(string encFilePath, string password)
        {
            Thread worker = new Thread(delegate()
            {
                try
                {
                    if (!File.Exists(encFilePath))
                    {
                        if (OperationCompleted != null)
                            OperationCompleted(false, "Encrypted file not found.");
                        return;
                    }

                    // Verify it's actually an encrypted file
                    if (!IsFileEncrypted(encFilePath))
                    {
                        if (OperationCompleted != null)
                            OperationCompleted(false, "File is not encrypted with this system.");
                        return;
                    }

                    using (FileStream fsInput = new FileStream(encFilePath, FileMode.Open, FileAccess.Read))
                    {
                        // Skip magic header (we already verified it)
                        fsInput.Seek(MagicHeader.Length, SeekOrigin.Begin);

                        // Read header
                        int extLen = fsInput.ReadByte();
                        byte[] extBytes = new byte[extLen];
                        fsInput.Read(extBytes, 0, extLen);
                        string originalExt = Encoding.UTF8.GetString(extBytes);

                        byte[] salt = new byte[SaltSize];
                        fsInput.Read(salt, 0, SaltSize);

                        byte[] iv = new byte[IvSize];
                        fsInput.Read(iv, 0, IvSize);

                        byte[] storedHash = new byte[HmacSize];
                        fsInput.Read(storedHash, 0, HmacSize);

                        // Initialize key variables before passing by reference
                        byte[] key = null;
                        byte[] hmacKey = null;
                        DeriveKeys(password, salt, out key, out hmacKey);

                        // Prepare output file
                        string outFile = Path.ChangeExtension(encFilePath, originalExt);
                        string tempFile = outFile + ".tmp";

                        // Decrypt the file
                        using (FileStream fsOutput = new FileStream(tempFile, FileMode.Create))
                        using (RijndaelManaged aes = new RijndaelManaged())
                        {
                            aes.KeySize = 256;
                            aes.BlockSize = 128;
                            aes.Mode = CipherMode.CBC;
                            aes.Padding = PaddingMode.PKCS7;

                            using (CryptoStream cryptoStream = new CryptoStream(fsInput, aes.CreateDecryptor(key, iv), CryptoStreamMode.Read))
                            {
                                CopyStreamWithProgress(cryptoStream, fsOutput, fsInput.Length - (MagicHeader.Length + 1 + extLen + SaltSize + IvSize + HmacSize));
                            }
                        }

                        // Verify the decrypted content
                        using (HMACSHA256 hmac = new HMACSHA256(hmacKey))
                        using (FileStream fs = new FileStream(tempFile, FileMode.Open, FileAccess.Read))
                        {
                            byte[] computedHash = hmac.ComputeHash(fs);
                            if (!CompareBytes(computedHash, storedHash))
                            {
                                File.Delete(tempFile);
                                if (OperationCompleted != null)
                                    OperationCompleted(false, "File integrity check failed. Possible tampering or wrong password.");
                                return;
                            }
                        }

                        // Replace encrypted file with decrypted version
                        File.Delete(encFilePath);
                        File.Move(tempFile, outFile);

                        LogActivity("DECRYPT_SUCCESS", encFilePath);
                        if (OperationCompleted != null)
                            OperationCompleted(true, "File decrypted successfully.");
                    }
                }
                catch (CryptographicException)
                {
                    LogActivity("DECRYPT_FAILED: Cryptographic error", encFilePath);
                    if (OperationCompleted != null)
                        OperationCompleted(false, "Decryption failed: Invalid password or corrupted file.");
                }
                catch (ThreadAbortException)
                {
                    // Clean up if operation was aborted
                    string outFile = Path.ChangeExtension(encFilePath, ".tmp");
                    if (File.Exists(outFile)) File.Delete(outFile);
                    LogActivity("DECRYPT_ABORTED", encFilePath);
                    if (OperationCompleted != null)
                        OperationCompleted(false, "Decryption was aborted.");
                }
                catch (Exception ex)
                {
                    LogActivity("DECRYPT_FAILED: " + ex.Message, encFilePath);
                    if (OperationCompleted != null)
                        OperationCompleted(false, "Decryption failed: " + ex.Message);
                }
            });

            worker.IsBackground = true;
            worker.Start();
        }

        // Derive both encryption key and HMAC key (.NET 2.0 compatible)
        private void DeriveKeys(string password, byte[] salt, out byte[] key, out byte[] hmacKey)
        {
            // Don't use Using statement with Rfc2898DeriveBytes in .NET 2.0
            Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(password, salt, Iterations);
            try
            {
                // Derive enough bytes for both keys
                byte[] masterKey = pbkdf2.GetBytes(KeySize + HmacSize);
                key = new byte[KeySize];
                hmacKey = new byte[HmacSize];
                Buffer.BlockCopy(masterKey, 0, key, 0, KeySize);
                Buffer.BlockCopy(masterKey, KeySize, hmacKey, 0, HmacSize);
            }
            finally
            {
                // Clean up resources manually
                if (pbkdf2 != null)
                {
                    pbkdf2.Reset();
                }
            }
        }

        // Compare byte arrays in constant time to prevent timing attacks
        private bool CompareBytes(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;

            int result = 0;
            for (int i = 0; i < a.Length; i++)
            {
                result |= (a[i] ^ b[i]);
            }

            return result == 0;
        }

        // Backup file (thread-safe)
        public static void BackupFile(string filePath)
        {
            try
            {
                string backupPath = filePath + ".bak";
                lock (typeof(Encryptor))
                {
                    if (!File.Exists(backupPath))
                    {
                        File.Copy(filePath, backupPath);
                    }
                }
            }
            catch
            {
                // Ignore backup errors
            }
        }

        // Generate cryptographically secure random bytes
        private static byte[] GenerateRandomBytes(int length)
        {
            byte[] bytes = new byte[length];
            lock (rngLock)
            {
                rng.GetBytes(bytes);
            }
            return bytes;
        }

        // Copy stream with progress reporting (.NET 2.0 compatible)
        private void CopyStreamWithProgress(Stream input, Stream output, long totalBytes)
        {
            int bufferSize = 8192; // Increased buffer size
            byte[] buffer = new byte[bufferSize];
            int bytesRead = 0;
            long totalRead = 0;

            do
            {
                bytesRead = input.Read(buffer, 0, bufferSize);
                if (bytesRead > 0)
                {
                    output.Write(buffer, 0, bytesRead);
                    totalRead += bytesRead;

                    // Report progress (0-100)
                    int progress = (int)((totalRead * 100) / totalBytes);
                    if (progress > 100) progress = 100;

                    if (ProgressChanged != null)
                        ProgressChanged(progress);
                }
            } while (bytesRead > 0);
        }

        // Thread-safe logging
        private static void LogActivity(string action, string filePath)
        {
            try
            {
                string logPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Arix_Encryptor.log");
                string logText = string.Format("{0:yyyy-MM-dd HH:mm:ss} | {1} | {2}",
                                           DateTime.Now,
                                           action,
                                           filePath);

                lock (typeof(Encryptor))
                {
                    File.AppendAllText(logPath, logText + Environment.NewLine);
                }
            }
            catch
            {
                // Ignore logging errors
            }
        }
    }
}
