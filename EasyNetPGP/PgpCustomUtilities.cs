using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using System;
using System.IO;

namespace EasyNetPGP
{
    /// <summary>
    /// Custom PGP Utility Methods.
    /// </summary>
    internal class PgpCustomUtilities
    {
        /// <summary>
        /// Compresses a file using the specified Compression Algorithm.
        /// </summary>
        /// <param name="fileName"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentException"></exception>
        internal static byte[] CompressFile(string fileName, CompressionAlgorithmTag algorithm)
        {
            // Parameter Checks
            if (String.IsNullOrEmpty(fileName)) { throw new ArgumentException("File Name Parameter is invalid."); }

            MemoryStream _memoryStream = new MemoryStream();
            PgpCompressedDataGenerator _compressedDataGen = new PgpCompressedDataGenerator(algorithm);
            PgpUtilities.WriteFileToLiteralData(_compressedDataGen.Open(_memoryStream), PgpLiteralData.Binary, new FileInfo(fileName));
            _compressedDataGen.Close();
            return _memoryStream.ToArray();
        }

        /// <summary>
        /// Search a secret key ring collection for a secret key corresponding to keyID if it exists.
        /// </summary>
        /// <param name="secretKeyRingBundle"></param>
        /// <param name="keyID"></param>
        /// <param name="passPhrase"></param>
        /// <returns></returns>
        /// <exception cref="PgpException"></exception>
        internal static PgpPrivateKey FindSecretKey(PgpSecretKeyRingBundle secretKeyRingBundle, long keyId, char[] passPhrase)
        {
            PgpSecretKey _pgpSecretKey = secretKeyRingBundle.GetSecretKey(keyId);

            if (_pgpSecretKey == null)
            {
                return null;
            }

            return _pgpSecretKey.ExtractPrivateKey(passPhrase);
        }

        internal static PgpPublicKey ReadPublicKey(string fileName)
        {
            using (Stream _publicKeyStream = File.OpenRead(fileName))
            {
                return ReadPublicKey(_publicKeyStream);
            }
        }

        /// <summary>
        /// Opens a key ring file and loads the first available key suitable for encryption.
        /// </summary>
        /// <param name="inputStream"></param>
        /// <returns></returns>
        /// <exception cref="IOException"></exception>
        /// <exception cref="PgpException"></exception>
        internal static PgpPublicKey ReadPublicKey(Stream inputStream)
        {
            PgpPublicKeyRingBundle _pgpPubKeyRingBundle = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(inputStream));

            foreach (PgpPublicKeyRing _pgpPubKeyRing in _pgpPubKeyRingBundle.GetKeyRings())
            {
                foreach (PgpPublicKey _pgpPubKey in _pgpPubKeyRing.GetPublicKeys())
                {
                    if (_pgpPubKey.IsEncryptionKey)
                    {
                        return _pgpPubKey;
                    }
                }
            }

            throw new ArgumentException("Encryption key not found in key ring.");
        }

        /// <summary>
        /// Gets a PgpSecretKey from a given file.
        /// </summary>
        /// <param name="fileName"></param>
        /// <returns></returns>
        internal static PgpSecretKey ReadSecretKey(string fileName)
        {
            // Parameter Checks
            if (String.IsNullOrEmpty(fileName)) { throw new ArgumentException("File Name Parameter is invalid."); }

            using (Stream _streamSecretKey = File.OpenRead(fileName))
            {
                return ReadSecretKey(_streamSecretKey);
            }
        }

        /// <summary>
        /// Opens a key ring file and loads the first available key suitable for signature generation.
        /// </summary>
        /// <param name="inputStream"></param>
        /// <returns></returns>
        /// <exception cref="IOException"></exception>
        /// <exception cref="PgpException"></exception>
        internal static PgpSecretKey ReadSecretKey(Stream inputStream)
        {
            PgpSecretKeyRingBundle _pgpSecKeyRingBundle = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(inputStream));

            foreach (PgpSecretKeyRing _pgpSecKeyRing in _pgpSecKeyRingBundle.GetKeyRings())
            {
                foreach (PgpSecretKey _pgpSecKey in _pgpSecKeyRing.GetSecretKeys())
                {
                    if (_pgpSecKey.IsSigningKey)
                    {
                        return _pgpSecKey;
                    }
                }
            }

            throw new ArgumentException("Signing key not found in key ring.");
        }
    }
}
