|AppVeyor|
|--------|
|[![Build status](https://ci.appveyor.com/api/projects/status/1yrq30re0bctbjvm?svg=true)](https://ci.appveyor.com/project/davisb10/easynetpgp)|

# EasyNetPGP

EasyNetPGP is an easy and straightforward PGP wrapper Library for .NET Framework / .NET Core.

The BouncyCastle Cryptography Libraries are utilized for Key Pair Generation, as well as Encryption and Decryption of files.

## Target Frameworks

* .NET Standard 1.3
* .NET Standard 2.0

## Installation

This package is available on NuGet from the following link:

[EasyNetPGP](https://www.nuget.org/packages/EasyNetPGP/)

## Use the Package

* Generate Public / Private Key Pairs
``` csharp
string username = "test@gmail.com";
string password = "password1";
string keyStorePath = @"C:\Temp";

// Uses the default Private / Public key file names
KeyGenerator.GenerateKeyPair(username, password, keyStorePath);

string privateKeyName = "private.asc";
string publicKeyName = "public.asc";

// Uses the provided Private / Public key file names
KeyGenerator.GenerateKeyPair(username, password, keyStorePath, privateKeyName, publicKeyName);
```

* Encrypt a File
``` csharp
string outFilePath = @"C:\Temp\SecretText.txt";
string inFilePath = @"C:\Temp\PlainText.txt";
string publicKeyFilePath = @"C:\Temp\public.asc";

PgpEncryptorDecryptor.EncryptFile(outFilePath, inFilePath, publicKeyFilePath);
```

* Decrypt a File
``` csharp
string inFilePath = @"C:\Temp\SecretText.txt";
string privateKeyFilePath = @"C:\Temp\private.asc";
string password = "password1";
string outFilePath = @"C:\Temp\PlainText.txt";

PgpEncryptorDecryptor.DecryptFile(inFilePath, privateKeyFilePath, password, outFilePath);
``` 
