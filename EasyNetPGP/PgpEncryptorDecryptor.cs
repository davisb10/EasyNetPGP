using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;
using System;
using System.IO;
using System.Threading.Tasks;

namespace EasyNetPGP
{
    /// <summary>
    ///     Used for Encryption and Decryption of files using PGP.
    /// </summary>
    public class PgpEncryptorDecryptor
    {
        #region Encryption

        /// <summary>
        ///     Asynchronously encrypts an input file given the provided Public Key File.
        /// </summary>
        /// <param name="outputFilePath"></param>
        /// <param name="inputFilePath"></param>
        /// <param name="publicKeyFilePath"></param>
        /// <param name="armor"></param>
        /// <param name="withIntegrityCheck"></param>
        /// <returns></returns>
        public async Task EncryptFileAsync(string outputFilePath, string inputFilePath, string publicKeyFilePath, bool armor = true, bool withIntegrityCheck = true)
        {
            await Task.Run(() => EncryptFile(inputFilePath, outputFilePath, publicKeyFilePath, armor, withIntegrityCheck));
        }

        /// <summary>
        ///     Encrypts an input file given the provided Public Key File.
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
            if (!File.Exists(publicKeyFilePath)) { throw new FileNotFoundException("Public Key File does not exist."); }

            PgpPublicKey _publicKey = PgpCustomUtilities.ReadPublicKey(publicKeyFilePath);

            using (Stream output = File.Create(outputFilePath))
            {
                EncryptFile(output, inputFilePath, _publicKey, armor, withIntegrityCheck);
            }
        }

        /// <summary>
        ///     Encrypts an input file stream given the provided Public Key File.
        /// </summary>
        /// <param name="outputFileStream">File Stream of the new encrypted output file.</param>
        /// <param name="inputFilePath">Path of existing unencrypted input file.</param>
        /// <param name="publicKey">PgpPublicKey that will be used to encrypt the file.</param>
        /// <param name="armor">Use ASCII Armor</param>
        /// <param name="withIntegrityCheck">Include Integrity Check</param>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="FileNotFoundException"></exception>
        private static void EncryptFile(Stream outputFileStream, string inputFilePath, PgpPublicKey publicKey, bool armor = true, bool withIntegrityCheck = true)
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

                FileInfo inputFile = new FileInfo(inputFilePath);
                Stream inputFileStream = File.OpenRead(inputFile.FullName);

                PgpCustomUtilities.WriteStreamToLiteralData(_compressedDataGen.Open(_encryptedOutStream), PgpLiteralData.Binary, inputFileStream, inputFile.Name);

                _compressedDataGen.Close();
                _encryptedOutStream.Dispose();
                inputFileStream.Dispose();

                if (armor)
                {
                    outputFileStream.Dispose();
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
        ///     Asynchronously decrypts the Input File, given the Private Key File, to the specified Decrypted File Path.
        /// </summary>
        /// <param name="inputFilePath">Full Path to existing encrypted file.</param>
        /// <param name="privateKeyFilePath">Full Path to existing Private Key.</param>
        /// <param name="password">Password that was used to encrypt the file.</param>
        /// <param name="decryptedFilePath"></param>
        /// <returns></returns>
        public async Task DecryptFileAsync(string inputFilePath, string privateKeyFilePath, string password, string decryptedFilePath)
        {
            await Task.Run(() => DecryptFile(inputFilePath, privateKeyFilePath, password, decryptedFilePath));
        }

        /// <summary>
        ///     Decrypts the Input File, given the Private Key File, to the specified Decrypted File Path.
        /// <para />
        ///     Note: if
        /// </summary>
        /// <param name="inputFilePath">Full Path to existing encrypted file.</param>
        /// <param name="privateKeyFilePath">Full Path to existing Private Key.</param>
        /// <param name="password">Password that was used to encrypt the file.</param>
        /// <param name="decryptedFilePath">Full Path of the new decrypted file.</param>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="FileNotFoundException"></exception>
        public static void DecryptFile(string inputFilePath, string privateKeyFilePath, string password, string decryptedFilePath)
        {
            // Parameter Checks
            if (String.IsNullOrEmpty(inputFilePath)) { throw new ArgumentException("Input File Path Parameter is invalid."); }
            if (String.IsNullOrEmpty(privateKeyFilePath)) { throw new ArgumentException("Private Key File Path Parameter is invalid."); }
            if (String.IsNullOrEmpty(password)) { throw new ArgumentException("Password Parameter is invalid."); }
            if (String.IsNullOrEmpty(decryptedFilePath)) { throw new ArgumentException("Decrypted File Path Parameter is invalid."); }

            if (!File.Exists(inputFilePath)) { throw new FileNotFoundException("Input File does not exist."); }
            if (!File.Exists(privateKeyFilePath)) { throw new FileNotFoundException("Private Key File does not exist."); }

            if (File.Exists(decryptedFilePath)) { throw new ArgumentException("Decrypted File already exists."); }

            using (Stream inputFileStream = File.OpenRead(inputFilePath))
            using (Stream privateKeyFileStream = File.OpenRead(privateKeyFilePath))
            {
                DecryptFile(inputFileStream, privateKeyFileStream, password, decryptedFilePath);
            }
        }

        /// <summary>
        ///     Decrypts the Input File stream, given the Private Key File stream, to the specified Decrypted File Path.
        /// </summary>
        /// <param name="inputFileStream">File Stream of encrypted file.</param>
        /// <param name="privateKeyFileStream">File Stream of Private Key file.</param>
        /// <param name="password">Password that was used to encrypt the file.</param>
        /// <param name="decryptedFilePath">Full Path of the new decrypted file.</param>
        private static void DecryptFile(Stream inputFileStream, Stream privateKeyFileStream, string password, string decryptedFilePath)
        {
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

            if (_pgpPrivateKey == null) { throw new ArgumentException("Secret key for message not found."); }

            Stream _privateKeyFileStream = _pgpPubKeyEncryptedData.GetDataStream(_pgpPrivateKey);

            PgpObjectFactory _pgpObjectFactoryPrivateKey = new PgpObjectFactory(_privateKeyFileStream);

            PgpCompressedData _pgpCompressedData = (PgpCompressedData)_pgpObjectFactoryPrivateKey.NextPgpObject();

            PgpObjectFactory _pgpObjectFactoryCompressedData = new PgpObjectFactory(_pgpCompressedData.GetDataStream());

            PgpObject _pgpObjectMessage = _pgpObjectFactoryCompressedData.NextPgpObject();

            if (_pgpObjectMessage is PgpLiteralData _pgpLiteralData)
            {
                FileInfo _decryptedFileInfo = new FileInfo(decryptedFilePath);

                string _outputFileName = _decryptedFileInfo.Name;
                string _outputFileDirectoryPath = _decryptedFileInfo.DirectoryName;
                Stream _outputFileStream = File.Create(Path.Combine(_outputFileDirectoryPath, _outputFileName));

                Stream _dataInputStream = _pgpLiteralData.GetInputStream();
                Streams.PipeAll(_dataInputStream, _outputFileStream);
                _outputFileStream.Dispose();
            }
            else if (_pgpObjectMessage is PgpCompressedData compressedData)
            {
                PgpObjectFactory of = null;

                using (Stream compressedDataInStream = compressedData.GetDataStream())
                {
                    of = new PgpObjectFactory(compressedDataInStream);
                }

                FileInfo _decryptedFileInfo = new FileInfo(decryptedFilePath);

                string _outputFileName = _decryptedFileInfo.Name;
                string _outputFileDirectoryPath = _decryptedFileInfo.DirectoryName;
                Stream _outputFileStream = File.Create(Path.Combine(_outputFileDirectoryPath, _outputFileName));

                _pgpObjectMessage = of.NextPgpObject();
                if (_pgpObjectMessage is PgpOnePassSignatureList)
                {
                    _pgpObjectMessage = of.NextPgpObject();
                    PgpLiteralData literalData = null;
                    literalData = (PgpLiteralData)_pgpObjectMessage;
                    Stream inputStream = literalData.GetInputStream();
                    Streams.PipeAll(inputStream, _outputFileStream);
                }
                else
                {
                    PgpLiteralData literalData = null;
                    literalData = (PgpLiteralData)_pgpObjectMessage;
                    Stream inputStream = literalData.GetInputStream();
                    Streams.PipeAll(inputStream, _outputFileStream);
                }
                _outputFileStream.Dispose();
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
