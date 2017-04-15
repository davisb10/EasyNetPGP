using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;
using System;
using System.IO;

namespace EasyNetPGP
{
    /// <summary>
    /// Used for Encryption and Decryption of files using PGP.
    /// </summary>
    public class PgpEncryptorDecryptor
    {
        #region Encryption

        /// <summary>
        /// Encrypts an input file given the provided Public Key File.
        /// </summary>
        /// <param name="outputFilePath">Path of new encrypted output file.</param>
        /// <param name="inputFilePath">Path of existing unencrypted input file.</param>
        /// <param name="publicKeyFilePath">Path of existing Pgp Public Key file.</param>
        /// <param name="armor">Use ASCII Armor</param>
        /// <param name="withIntegrityCheck">Include Integrity Check</param>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="FileNotFoundException"></exception>
        public static void EncryptFile(string outputFilePath, string inputFilePath, string publicKeyFilePath, bool armor = true, bool withIntegrityCheck = true)
        {
            // Parameter Checks
            if (String.IsNullOrEmpty(outputFilePath)) { throw new ArgumentException("Output File Name Parameter is invalid."); }
            if (String.IsNullOrEmpty(inputFilePath)) { throw new ArgumentException("Input File Name Parameter is invalid."); }
            if (String.IsNullOrEmpty(publicKeyFilePath)) { throw new ArgumentException("Public Key File Name Parameter is invalid."); }

            if (!File.Exists(inputFilePath)) { throw new FileNotFoundException("Input File does not exist."); }
            if (!File.Exists(publicKeyFilePath)) { throw new FileNotFoundException("Public Key File does not exist"); }

            PgpPublicKey _publicKey = PgpCustomUtilities.ReadPublicKey(publicKeyFilePath);

            using (Stream output = File.Create(outputFilePath))
            {
                EncryptFile(output, inputFilePath, _publicKey, armor, withIntegrityCheck);
            }
        }

        /// <summary>
        /// Encrypts an input file stream given the provided Public Key File.
        /// </summary>
        /// <param name="outputFileStream">File Stream of the new encrypted output file.</param>
        /// <param name="inputFilePath">Path of existing unencrypted input file.</param>
        /// <param name="publicKey">PgpPublicKey that will be used to encrypt the file.</param>
        /// <param name="armor">Use ASCII Armor</param>
        /// <param name="withIntegrityCheck">Include Integrity Check</param>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="FileNotFoundException"></exception>
        public static void EncryptFile(Stream outputFileStream, string inputFilePath, PgpPublicKey publicKey, bool armor = true, bool withIntegrityCheck = true)
        {
            // Parameter Checks
            if (String.IsNullOrEmpty(inputFilePath)) { throw new ArgumentException("Input File Name Parameter is invalid."); }

            if (!File.Exists(inputFilePath)) { throw new FileNotFoundException("Input File does not exist."); }

            if (armor)
            {
                outputFileStream = new ArmoredOutputStream(outputFileStream);
            }

            try
            {
                PgpEncryptedDataGenerator _encryptedDataGen = new PgpEncryptedDataGenerator(SymmetricKeyAlgorithmTag.Cast5, withIntegrityCheck, new SecureRandom());

                _encryptedDataGen.AddMethod(publicKey);

                Stream _encryptedOutStream = _encryptedDataGen.Open(outputFileStream, new byte[1 << 16]);

                PgpCompressedDataGenerator _compressedDataGen = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);

                PgpUtilities.WriteFileToLiteralData(_compressedDataGen.Open(_encryptedOutStream), PgpLiteralData.Binary, new FileInfo(inputFilePath), new byte[1 << 16]);

                _compressedDataGen.Close();
                _encryptedOutStream.Close();

                if (armor)
                {
                    outputFileStream.Close();
                }
            }
            catch (PgpException ex)
            {
                Console.Error.WriteLine(ex);

                Exception underlyingException = ex.InnerException;
                if (underlyingException != null)
                {
                    Console.Error.WriteLine(underlyingException.Message);
                    Console.Error.WriteLine(underlyingException.StackTrace);
                }
            }
        }

        #endregion

        #region Decryption

        /// <summary>
        /// Decrypts the Input File, given the Private Key File, to the specified Decrypted File Path.
        /// </summary>
        /// <param name="inputFilePath">Path to existing encrypted file.</param>
        /// <param name="privateKeyFilePath">Path to existing Private Key.</param>
        /// <param name="password">Password that was used to encrypt the file.</param>
        /// <param name="decryptedFileName">Path of the new decrypted file.</param>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="FileNotFoundException"></exception>
        public static void DecryptFile(string inputFilePath, string privateKeyFilePath, string password, string decryptedFileName)
        {
            // Parameter Checks
            if (String.IsNullOrEmpty(inputFilePath)) { throw new ArgumentException("Input File Name Parameter is invalid."); }
            if (String.IsNullOrEmpty(privateKeyFilePath)) { throw new ArgumentException("Private Key File Name is invalid"); }
            if (String.IsNullOrEmpty(password)) { throw new ArgumentException("Password Parameter is invalid"); }
            if (String.IsNullOrEmpty(decryptedFileName)) { throw new ArgumentException("Decrypted File Name Parameter is invalid."); }

            if (!File.Exists(inputFilePath)) { throw new FileNotFoundException("Input File does not exist."); }
            if (!File.Exists(privateKeyFilePath)) { throw new FileNotFoundException("Private Key File does not exist."); }

            using (Stream inputFileStream = File.OpenRead(inputFilePath))
            using (Stream privateKeyFileStream = File.OpenRead(privateKeyFilePath))
            {
                DecryptFile(inputFileStream, privateKeyFileStream, password, decryptedFileName);
            }
        }

        /// <summary>
        /// Decrypts the Input File stream, given the Private Key File stream, to the specified Decrypted File Path.
        /// </summary>
        /// <param name="inputFileStream">File Stream of encrypted file.</param>
        /// <param name="privateKeyFileStream">File Stream of Private Key file.</param>
        /// <param name="password">Password that was used to encrypt the file.</param>
        /// <param name="decryptedFilePath">Path of the new decrypted file.</param>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="PgpException"></exception>
        private static void DecryptFile(Stream inputFileStream, Stream privateKeyFileStream, string password, string decryptedFilePath)
        {
            // Parameter Checks
            if (String.IsNullOrEmpty(password)) { throw new ArgumentException("Password Parameter is invalid."); }
            if (String.IsNullOrEmpty(decryptedFilePath)) { throw new ArgumentException("Decrypted File Name Parameter is invalid."); }

            inputFileStream = PgpUtilities.GetDecoderStream(inputFileStream);

            PgpObjectFactory _pgpObjectFactory = new PgpObjectFactory(inputFileStream);
            PgpEncryptedDataList _pgpEncryptedDataList;

            PgpObject _pgpObject = _pgpObjectFactory.NextPgpObject();
            if (_pgpObject is PgpEncryptedDataList)
            {
                _pgpEncryptedDataList = (PgpEncryptedDataList)_pgpObject;
            }
            else
            {
                _pgpEncryptedDataList = (PgpEncryptedDataList)_pgpObjectFactory.NextPgpObject();
            }

            PgpPrivateKey _pgpPrivateKey = null;
            PgpPublicKeyEncryptedData _pgpPubKeyEncryptedData = null;
            PgpSecretKeyRingBundle _pgpSecKeyRingBundle = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyFileStream));

            foreach (PgpPublicKeyEncryptedData _pgpPubKeyEncData in _pgpEncryptedDataList.GetEncryptedDataObjects())
            {
                _pgpPrivateKey = PgpCustomUtilities.FindSecretKey(_pgpSecKeyRingBundle, _pgpPubKeyEncData.KeyId, password.ToCharArray());

                if (_pgpPrivateKey != null)
                {
                    _pgpPubKeyEncryptedData = _pgpPubKeyEncData;
                    break;
                }
            }

            if (_pgpPrivateKey == null) { throw new ArgumentException("secret key for message not found."); }

            Stream _privateKeyFileStream = _pgpPubKeyEncryptedData.GetDataStream(_pgpPrivateKey);

            PgpObjectFactory _pgpObjectFactoryPrivateKey = new PgpObjectFactory(_privateKeyFileStream);

            PgpCompressedData _pgpCompressedData = (PgpCompressedData)_pgpObjectFactoryPrivateKey.NextPgpObject();

            PgpObjectFactory _pgpObjectFactoryCompressedData = new PgpObjectFactory(_pgpCompressedData.GetDataStream());

            PgpObject _pgpObjectMessage = _pgpObjectFactoryCompressedData.NextPgpObject();

            if (_pgpObjectMessage is PgpLiteralData)
            {
                PgpLiteralData _pgpLiteralData = (PgpLiteralData)_pgpObjectMessage;

                string _outputFileName = _pgpLiteralData.FileName;
                string _outputFileDirectoryPath;
                Stream _outputFileStream;
                if (_outputFileName.Length == 0)
                {
                    _outputFileName = decryptedFilePath;
                    _outputFileStream = File.Create(_outputFileName);
                }
                else
                {
                    FileInfo _decryptedFileInfo = new FileInfo(decryptedFilePath);
                    _outputFileDirectoryPath = _decryptedFileInfo.DirectoryName;
                    _outputFileStream = File.Create(Path.Combine(_outputFileDirectoryPath, _outputFileName));
                }

                Stream _dataInputStream = _pgpLiteralData.GetInputStream();
                Streams.PipeAll(_dataInputStream, _outputFileStream);
                _outputFileStream.Close();
            }
            else if (_pgpObjectMessage is PgpOnePassSignatureList) { throw new PgpException("Encrypted message contains a signed message - not literal data."); }
            else { throw new PgpException("Message is not a simple encrypted file - type unknown."); }

            if (_pgpPubKeyEncryptedData.IsIntegrityProtected())
            {
                if (!_pgpPubKeyEncryptedData.Verify()) { throw new PgpException("Message failed integrity check."); }
            }
        }

        #endregion
    }
}
