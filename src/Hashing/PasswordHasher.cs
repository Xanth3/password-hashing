using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Konscious.Security.Cryptography;

namespace Password.Hashing
{
    /// <summary>
    /// Computes and verifies hashes of passwords.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Note that the settings are important - creating two instances of this class with
    /// different hash sizes, iterations, parallelism, etc., will result in different hashes
    /// being generated (and being unable to verify a hash created with different settings).
    /// </para>
    /// <para>
    /// It's the responsibility of developers using this library to ensure that they
    /// correctly configure their hashing through constants or other configuration values.
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    ///     var hasher = new PasswordHasher(
    ///         hashSize: 64,
    ///         saltLength: 32,
    ///         iterations: 10);
    ///     
    ///     hasher.Hash("my password", out var hash, out var salt);
    ///     var validPassword = hasher.Verify("my password", hash, salt);
    /// </code>
    /// </example>
    public sealed class PasswordHasher
    {
        private const string Base64Expression = @"^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$";

        private static readonly Lazy<PasswordHasher> DefaultLazy = new Lazy<PasswordHasher>(() => new PasswordHasher(), false);

        private static readonly Regex Base64Regex = new Regex(Base64Expression, RegexOptions.Compiled | RegexOptions.CultureInvariant);

        private readonly int _hashSize;
        private readonly int _saltLength;
        private readonly int _iterations;
        private readonly int _parallelism;
        private readonly int _memorySize;
        private readonly byte[] _knownSecret;
        private readonly IEncryptionProvider _encryptionProvider;

        /// <summary>
        /// Instantiates a new instance of the <see cref="PasswordHasher" /> class.
        /// </summary>
        /// <param name="hashSize">Size in bytes of the resulting hash (minimum is 4)</param>
        /// <param name="saltLength">Length in bytes of the salt to generate (minimum is 4)</param>
        /// <param name="iterations">The number of iterations to perform to compute the hash (minimum of 1)</param>
        /// <param name="parallelism">Degree of parallelism specifies how many of these lanes will be used to generate the hash (between 1 and 10)</param>
        /// <param name="memorySize">The amount of memory (in Kilobytes) to use to calculate the hash (minimum is 8)</param>
        /// <param name="knownSecret">Optional secret as a byte array (can be any well-known sequence of bytes, either hard-coded or from an external source)</param>
        /// <param name="encryptionProvider">Optional encryption provider - if provided, hashes and salt will be encrypted using this provider</param>
        /// <exception cref="ArgumentOutOfRangeException">The hash length must be greater than or equal to 4</exception>
        /// <exception cref="ArgumentOutOfRangeException">The salt length must be greater than or equal to 4</exception>
        /// <exception cref="ArgumentOutOfRangeException">The degree of parallelism must be between 1 and 10</exception>
        /// <exception cref="ArgumentOutOfRangeException">The memory size must be greater than or equal to 8</exception>
        public PasswordHasher(
            int hashSize = PasswordHasherDefaults.HashSize,
            int saltLength = PasswordHasherDefaults.SaltLength,
            int iterations = PasswordHasherDefaults.Iterations,
            int parallelism = PasswordHasherDefaults.Parallelism,
            int memorySize = PasswordHasherDefaults.MemorySize,
            byte[] knownSecret = null,
            IEncryptionProvider encryptionProvider = null)
        {
            if (hashSize < 4)
            {
                throw new ArgumentOutOfRangeException($"The hash length must be greater than or equal to 4 ({hashSize} was provided)");
            }

            if (saltLength < 4)
            {
                throw new ArgumentOutOfRangeException($"The salt length must be greater than or equal to 4 ({saltLength} was provided)");
            }

            if (iterations < 1)
            {
                throw new ArgumentOutOfRangeException($"The number of iterations must be greater than or equal to 1 ({iterations} was provided)");
            }

            if (parallelism < 1 || parallelism > 10)
            {
                throw new ArgumentOutOfRangeException($"The degree of parallelism must be between 1 and 10 ({parallelism} was provided)");
            }

            if (memorySize < 8)
            {
                throw new ArgumentOutOfRangeException($"The memory size must be greater than or equal to 8 ({memorySize} was provided)");
            }

            _hashSize = hashSize;
            _saltLength = saltLength;
            _iterations = iterations;
            _parallelism = parallelism;
            _memorySize = memorySize;
            _knownSecret = knownSecret;
            _encryptionProvider = encryptionProvider;
        }

        /// <summary>
        /// Gets a default instance of <see cref="PasswordHasher" /> with default parameters.
        /// </summary>
        /// <remarks>
        /// Uses the parameters defined in <see cref="PasswordHasherDefaults" />.
        /// </remarks>
        public static PasswordHasher Default => DefaultLazy.Value;

        /// <summary>
        /// Hashes a given password and provides the results in <paramref name="hash"/> and <paramref name="salt"/>.
        /// </summary>
        /// <param name="password">Plain-text password to hash</param>
        /// <param name="hash">Resulting password hash as a base64-encoded string</param>
        /// <param name="salt">Generated random salt as a base64-encoded string</param>
        /// <param name="associatedData">Additional data to include in the hash</param>
        /// <exception cref="ArgumentNullException">Failed to compute a password hash because the given password is null, empty or whitespace</exception>
        public void Hash(string password, out string hash, out string salt, byte[] associatedData = null)
        {
            if (string.IsNullOrWhiteSpace(password))
            {
                throw new ArgumentNullException(nameof(password), "Failed to compute a password hash because the given password is null, empty or whitespace");
            }

            var saltBytes = GenerateSalt();
            var hashBytes = ComputeHash(password, saltBytes, associatedData);

            // if set to use encryption, encrypt both the salt and hash with the given AES parameters
            if (_encryptionProvider != null)
            {
                saltBytes = _encryptionProvider.EncryptBytes(saltBytes);
                hashBytes = _encryptionProvider.EncryptBytes(hashBytes);
            }

            hash = EncodeBytes(hashBytes);
            salt = EncodeBytes(saltBytes);
        }

        /// <summary>
        /// Verifies a plaintext password against a known hash and salt.
        /// </summary>
        /// <param name="providedPassword">Plaintext password to verify</param>
        /// <param name="hash">Password hash to verify against (expects a base-64 encoded string)</param>
        /// <param name="salt">Salt value for the password hash (expects a base-64 encoded string)</param>
        /// <param name="associatedData">Additional data to include verify against the hash</param>
        /// <returns>A boolean value indicating whether the provided password matches the hash.</returns>
        /// <exception cref="ArgumentNullException">The provided hash cannot be a null, empty or whitespace string</exception>
        /// <exception cref="ArgumentNullException">The provided salt cannot be a null, empty or whitespace string</exception>
        /// <exception cref="ArgumentException">The given hash must be in the format of a base64-encoded string</exception>
        /// <exception cref="ArgumentException">The given salt must be in the format of a base64-encoded string</exception>
        /// <exception cref="CryptographicException">Cannot verify provided password because encryption is enabled on this instance, but the keys provided cannot decrypt the hash and/or salt. This means that either the provided hash/salt were never encrypted, or that they were encrypted using different keys, or that they were encrypted using a different encryption provider.</exception>
        public bool Verify(string providedPassword, string hash, string salt, byte[] associatedData = null)
        {
            if (string.IsNullOrWhiteSpace(providedPassword))
            {
                return false;
            }

            if (string.IsNullOrWhiteSpace(hash))
            {
                throw new ArgumentNullException(nameof(hash), "The provided hash cannot be a null, empty or whitespace string");
            }

            if (string.IsNullOrWhiteSpace(salt))
            {
                throw new ArgumentNullException(nameof(salt), "The provided salt cannot be a null, empty or whitespace string");
            }

            if (!IsBase64(hash))
            {
                throw new ArgumentException("The given hash must be in the format of a base64-encoded string", nameof(hash));
            }

            if (!IsBase64(salt))
            {
                throw new ArgumentException("The given salt must be in the format of a base64-encoded string", nameof(salt));
            }

            var hashBytes = DecodeBytes(hash);
            var saltBytes = DecodeBytes(salt);

            if (_encryptionProvider != null)
            {
                try
                {
                    hashBytes = _encryptionProvider.DecryptBytes(hashBytes);
                    saltBytes = _encryptionProvider.DecryptBytes(saltBytes);
                }
                catch (CryptographicException ex)
                {
                    throw new CryptographicException("Cannot verify provided password because encryption is enabled on this instance, but the keys provided cannot decrypt the hash and/or salt. This means that either the provided hash/salt were never encrypted, or that they were encrypted using different keys, or that they were encrypted using a different encryption provider.", ex);
                }
            }

            var compareHashBytes = ComputeHash(providedPassword, saltBytes, associatedData);

            return compareHashBytes.SequenceEqual(hashBytes);
        }

        private static byte[] GetPasswordBytes(string password) => Encoding.UTF8.GetBytes(password);

        private static string EncodeBytes(byte[] hashBytes) => Convert.ToBase64String(hashBytes);

        private static byte[] DecodeBytes(string salt) => Convert.FromBase64String(salt);

        private static bool IsBase64(string input) => Base64Regex.IsMatch(input);

        private byte[] ComputeHash(string password, byte[] salt, byte[] associatedData)
        {
            var passwordBytes = GetPasswordBytes(password);

            var argon = new Argon2id(passwordBytes)
            {
                Salt = salt,
                DegreeOfParallelism = _parallelism,
                Iterations = _iterations,
                MemorySize = _memorySize,
                KnownSecret = _knownSecret,
                AssociatedData = associatedData
            };

            return argon.GetBytes(_hashSize);
        }

        private byte[] GenerateSalt()
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                var salt = new byte[_saltLength];
                rng.GetBytes(salt);
                return salt;
            }
        }
    }
}
