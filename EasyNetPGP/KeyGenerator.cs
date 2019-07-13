using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System;
using System.IO;

namespace EasyNetPGP
{
    /// <summary>
    ///     Used to generate PGP Public and Private Key Pairs.
    /// </summary>
    public static class KeyGenerator
    {
        /// <summary>
        ///     Generates a Public and Private Key Pair.
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <param name="keyStorePath">Folder Name where the Keys will be stored.</param>
        /// <param name="privateKeyFileName">Name of the Private Key File.</param>
        /// <param name="publicKeyFileName">Name of the Public Key File.</param>
        /// <exception cref="ArgumentException">Invalid Parameter Values</exception>
        public static void GenerateKeyPair(string username, string password, string keyStorePath, string privateKeyFileName = "PGPPrivateKey.asc", string publicKeyFileName = "PGPPublicKey.asc")
        {
            // Parameter Checks
            if (String.IsNullOrEmpty(username)) { throw new ArgumentException("Username Parameter is invalid."); }
            if (String.IsNullOrEmpty(password)) { throw new ArgumentException("Password Parameter is invalid."); }
            if (String.IsNullOrEmpty(keyStorePath)) { throw new ArgumentException("Key Store Path Parameter is invalid."); }
            if (String.IsNullOrEmpty(privateKeyFileName)) { throw new ArgumentException("Private Key File Name Parameter is invalid."); }
            if (String.IsNullOrEmpty(publicKeyFileName)) { throw new ArgumentException("Public Key File Name Parameter is invalid."); }

            if (!privateKeyFileName.ToLower().EndsWith(".asc")) { throw new ArgumentException("Private Key File Extension is not valid."); }
            if (!publicKeyFileName.ToLower().EndsWith(".asc")) { throw new ArgumentException("Public Key File Extension is not valid."); }

            if (!Directory.Exists(keyStorePath)) { throw new ArgumentException("Key Store Path Parameter does not match an existing directory."); }

            IAsymmetricCipherKeyPairGenerator _keyPairGenerator = new RsaKeyPairGenerator();
            _keyPairGenerator.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x13), new SecureRandom(), 1024, 8));
            AsymmetricCipherKeyPair _keyPair = _keyPairGenerator.GenerateKeyPair();
            FileStream _fileStreamPrivate = new FileInfo(Path.Combine(keyStorePath, privateKeyFileName)).OpenWrite();
            FileStream _fileStreamPublic = new FileInfo(Path.Combine(keyStorePath, publicKeyFileName)).OpenWrite();
            ExportKeyPair(_fileStreamPrivate, _fileStreamPublic, _keyPair.Public, _keyPair.Private, username, password.ToCharArray(), true);
            _fileStreamPrivate.Dispose();
            _fileStreamPublic.Dispose();
        }

        /// <summary>
        ///     Private method that exports the keys to their respective files. 
        /// </summary>
        /// <param name="secretOut"></param>
        /// <param name="publicOut"></param>
        /// <param name="publicKey"></param>
        /// <param name="privateKey"></param>
        /// <param name="identity"></param>
        /// <param name="passPhrase"></param>
        /// <param name="armor"></param>
        private static void ExportKeyPair(Stream secretOut, Stream publicOut, AsymmetricKeyParameter publicKey, AsymmetricKeyParameter privateKey, string identity, char[] passPhrase, bool armor)
        {
            if (armor) secretOut = new ArmoredOutputStream(secretOut);

            PgpSecretKey _secretKey = new PgpSecretKey(PgpSignature.DefaultCertification, PublicKeyAlgorithmTag.RsaGeneral, publicKey, privateKey, DateTime.Now, identity, SymmetricKeyAlgorithmTag.Cast5, passPhrase, null, null, new SecureRandom());
            _secretKey.Encode(secretOut);
            secretOut.Dispose();

            if (armor) publicOut = new ArmoredOutputStream(publicOut);

            PgpPublicKey _publicKey = _secretKey.PublicKey;
            _publicKey.Encode(publicOut);
            publicOut.Dispose();
        }
    }
}
