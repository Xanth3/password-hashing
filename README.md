# Password Hashing Library

Provides a common password hashing implementation with friendly setup options. The library can be included as a NuGet package or directly as a DLL.

## Usage

The key object is the `PasswordHasher` class. This can be instantiated either per-request or as a shared object; it stores no state other than its configuration, and is immutable. The public API consists of two methods:

```csharp
// hashes a given password
void Hash(string password, out string hash, out string salt)

// verifies a plain-text password against a hash/salt
bool Verify(string providedPassword, string hash, string salt)
```

To create a hash of a password:

```csharp
string hash;
string salt;

var hasher = new PasswordHasher();
hasher.Hash("my password", out hash, out salt);

// TODO: save the hash and salt in a database
Console.WriteLine(hash);
Console.WriteLine(salt);
```

To verify a provided password against a known hash:

```csharp
var user = GetDatabaseUser(); // assume that you have a method like this to get database values

var providedPassword = "password123";

var hasher = new PasswordHasher();

var verificationResult = hasher.Verify(providedPasswor, user.PasswordHash, user.PasswordSalt);
Console.WriteLine(verificationResult);
```

## Advanced usage

The parameters of the hasher can be set in the constructor. Basic parameters can be set as follows:

```csharp
var hasher = new PasswordHasher
(
	hashSize: 512,
	saltLength: 64,
	iterations: 10,
	parallelism: 8,
	memorySize: 1024
);
```

Note that the options which you select will affect the hashes that are produced - in other words, if you spin up two instances of the hasher with different parameters, then they will produce different hashes from the same input.

### Known Secrets

Argon2 allows you to use a well-known "secret" to provide an extra layer of security to hashes. This secret is an array of bytes; where it comes from is up to developers, whether that's a constant value or something that's loaded from an external resource. To use it, you just need to provide it in the constructor:

```csharp
var secret = System.Text.Encoding.UTF8.GetBytes("anteater");

var hasher = new PasswordHasher(knownSecret: secret);
```

### Associated data

Argon2 allows you to add associated data to a hash; this is intended to be data that is not a static "secret", but something that is associated with the data being hashed. In practical terms, this would be a static bit of data about the user account: for example, the user GUID.

> **Important** - this must be a value that never changes; if it does change, the hash can no longer be verified.

To use this, try:

```csharp
var hasher = new PasswordHasher();
var associatedData = user.UserGuid.ToByteArray();
hasher.Hash(providedPassword, out var hash, out var salt, associatedData);
```

The parameter is optional, but once used in a hash, must always be supplied in order to verify it.

### Encrypting the hash and salt

For extra security, you can encrypt the hash and salt that the hasher creates. In practice, you are expected to store the keys outside of the database containing the hashes - either in an external file or in a constant in code. To do this, you need to supply encryption parameters to the hasher:

```csharp
byte[] key = GetKeyBytes(); // TODO: implement this
byte[] iv = GetIVBytes();   // TODO: implement this

var encryptor = new AesEncryptionProvider(key, iv);

var hasher = new PasswordHasher(encryptionProvider: encryptor);
```

If you want to store the encryption keys on the file system, `AesEncryptionProvider` gives you some helper methods to serialize and deserialize the values to and from XML:

```csharp
var original = new AesEncryptionProvider(key, iv);

var xml = p.ToXmlString();

var deserialized = AesEncryptionProvider.FromXmlString(xml);
```

Note that if you use encryption on your hashes, you must retain the original keys for as long as the hashes are kept, otherwise you will not be able to verify passwords. To mitigate against the risk of key disclosure, consider a key rotation strategy, whereby keys are routinely updated, and passwords are re-hashed with a new key when one is available.

### Using a custom encryption provider

If you want to use something other than AES, then you just need to implement `IEncryptionProvider` and pass it into `PasswordHasher`.