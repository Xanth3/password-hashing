using System;
using System.Security.Cryptography;
using System.Text;
using Xunit;
using Xunit.Abstractions;

namespace Password.Hashing.Test
{
    public class PasswordHasherTests
    {
        private readonly ITestOutputHelper testOutputHelper;

        public PasswordHasherTests(ITestOutputHelper testOutputHelper)
        {
            this.testOutputHelper = testOutputHelper;
        }

        [Fact]
        public void Can_Verify_Hashed_Password()
        {
            // arrange
            var target = new PasswordHasher();
            var password = "I am a servant of the Secret Fire, wielder of the Flame of Anor";

            // act
            target.Hash(password, out var hash, out var salt);

            // assert
            Assert.True(target.Verify(password, hash, salt));
        }

        [Fact]
        public void Can_Verify_Hashed_Password_With_Secret()
        {
            // arrange
            var secret = new byte[] { 0xf, 0xf, 0xf, 0xa, 0xc, 0xd };
            var target = new PasswordHasher(knownSecret: secret);

            var password = "I am a servant of the Secret Fire, wielder of the Flame of Anor";

            // act
            target.Hash(password, out var hash, out var salt);

            // assert
            Assert.True(target.Verify(password, hash, salt));
        }

        [Fact]
        public void Cannot_Verify_Hashed_Password_Without_Secret()
        {
            // arrange
            var secret = new byte[] { 0xf, 0xf, 0xf, 0xa, 0xc, 0xd };
            var target = new PasswordHasher(knownSecret: secret);

            var password = "I am a servant of the Secret Fire, wielder of the Flame of Anor";

            // act
            target.Hash(password, out var hash, out var salt);
            target = new PasswordHasher();

            // assert
            Assert.False(target.Verify(password, hash, salt));
        }

        [Fact]
        public void Can_Verify_Hashed_Password_With_AssociatedData()
        {
            // arrange
            var target = new PasswordHasher();
            var data = Guid.NewGuid().ToByteArray();
            var password = "I am a servant of the Secret Fire, wielder of the Flame of Anor";

            // act
            target.Hash(password, out var hash, out var salt, data);

            // assert
            Assert.True(target.Verify(password, hash, salt, data));
        }

        [Fact]
        public void Canot_Verify_Hashed_Password_Without_AssociatedData()
        {
            // arrange
            var target = new PasswordHasher();
            var data = Guid.NewGuid().ToByteArray();
            var password = "I am a servant of the Secret Fire, wielder of the Flame of Anor";

            // act
            target.Hash(password, out var hash, out var salt, data);

            // assert
            Assert.False(target.Verify(password, hash, salt));
        }

        [Fact]
        public void Canot_Verify_Hashed_Password_With_Invalid_AssociatedData()
        {
            // arrange
            var target = new PasswordHasher();

            var rightData = Guid.NewGuid().ToByteArray();
            var wrongData = Guid.NewGuid().ToByteArray();

            var password = "I am a servant of the Secret Fire, wielder of the Flame of Anor";

            // act
            target.Hash(password, out var hash, out var salt, rightData);

            // assert
            Assert.False(target.Verify(password, hash, salt, wrongData));
        }

        [Fact]
        public void Cannot_Verify_Incorrect_Password()
        {
            // arrange
            var target = new PasswordHasher();
            var password = "I am a servant of the Secret Fire, wielder of the Flame of Anor";
            var wrongPassword = "The dark fire will not avail you, flame of Udun";

            // act
            target.Hash(password, out var hash, out var salt);

            // assert
            Assert.False(target.Verify(wrongPassword, hash, salt));
        }

        [Fact]
        public void Cannot_Verify_Incorrect_Salt()
        {
            // arrange
            var target = new PasswordHasher();
            var password = "I am a servant of the Secret Fire, wielder of the Flame of Anor";
            var wrongSalt = Convert.ToBase64String(Encoding.UTF8.GetBytes("123456"));

            // act
            target.Hash(password, out var hash, out _);

            // assert
            Assert.False(target.Verify(password, hash, wrongSalt));
        }

        [Fact]
        public void Hash_Produces_Different_Result()
        {
            // arrange
            var target = new PasswordHasher();
            var password = "password123";

            // act
            target.Hash(password, out var hash1, out _);
            target.Hash(password, out var hash2, out _);

            // assert
            Assert.NotEqual(hash1, hash2);
        }

        [Theory]
        [InlineData("")]
        [InlineData(" ")]
        [InlineData(null)]
        public void Hash_Throws_ArgumentNullException_For_Empty_Null_Or_Whitespace(string password)
        {
            // arrange
            var target = new PasswordHasher();

            // act/assert
            Assert.Throws<ArgumentNullException>(() =>
                target.Hash(password, out _, out _));
        }

        [Theory]
        [InlineData("")]
        [InlineData(" ")]
        [InlineData(null)]
        public void Returns_False_For_Empty_Password(string providedPassword)
        {
            // arrange
            var target = new PasswordHasher();
            var password = "I am a servant of the Secret Fire, wielder of the Flame of Anor";

            // act
            target.Hash(password, out var hash, out var salt);

            // assert
            Assert.False(target.Verify(providedPassword, hash, salt));
        }

        [Fact]
        public void Uses_Aes_If_Provided()
        {
            // arrange
            var tempKey = Aes.Create();
            var encParams = new AesEncryptionProvider(tempKey.Key, tempKey.IV);
            var target = new PasswordHasher(encryptionProvider: encParams);
            var password = "I am a servant of the Secret Fire, wielder of the Flame of Anor";

            // act
            target.Hash(password, out var hash, out var salt);

            // assert
            Assert.True(target.Verify(password, hash, salt));
        }

        [Fact]
        public void Throws_Exception_If_Encryption_Keys_Invalid()
        {
            // arrange
            var tempKey1 = Aes.Create();
            var tempKey2 = Aes.Create();

            var hasher1 = new PasswordHasher(encryptionProvider: new AesEncryptionProvider(tempKey1.Key, tempKey1.IV));
            var hasher2 = new PasswordHasher(encryptionProvider: new AesEncryptionProvider(tempKey2.Key, tempKey2.IV));

            var password = "I am a servant of the Secret Fire, wielder of the Flame of Anor";

            // act
            hasher1.Hash(password, out var hash, out var salt);

            // assert
            Assert.Throws<CryptographicException>(() => hasher2.Verify(password, hash, salt));
        }

        [Fact]
        public void Throws_Exception_If_No_Encryption_Used_In_Hash()
        {
            // arrange
            var tempKey = Aes.Create();

            var hasher1 = new PasswordHasher(encryptionProvider: null);
            var hasher2 = new PasswordHasher(encryptionProvider: new AesEncryptionProvider(tempKey.Key, tempKey.IV));

            var password = "I am a servant of the Secret Fire, wielder of the Flame of Anor";

            // act
            hasher1.Hash(password, out var hash, out var salt);

            // assert
            Assert.Throws<CryptographicException>(() => hasher2.Verify(password, hash, salt));
        }

        [Fact]
        public void Cannot_Verify_Password_If_No_Encryption_Keys_Provided()
        {
            // arrange
            var tempKey = Aes.Create();

            var hasher1 = new PasswordHasher(encryptionProvider: new AesEncryptionProvider(tempKey.Key, tempKey.IV));
            var hasher2 = new PasswordHasher(encryptionProvider: null);

            var password = "I am a servant of the Secret Fire, wielder of the Flame of Anor";

            // act
            hasher1.Hash(password, out var hash, out var salt);

            // assert
            Assert.False(hasher2.Verify(password, hash, salt));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(-1)]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        public void Constructor_Throws_ArgumentOutOfRangeException_For_Invalid_HashSize(int hashSize)
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new PasswordHasher(hashSize: hashSize));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(-1)]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        public void Constructor_Throws_ArgumentOutOfRangeException_For_Invalid_SaltLength(int saltLength)
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new PasswordHasher(saltLength: saltLength));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(-1)]
        public void Constructor_Throws_ArgumentOutOfRangeException_For_Invalid_Iterations(int iterations)
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new PasswordHasher(iterations: iterations));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(-1)]
        [InlineData(11)]
        public void Constructor_Throws_ArgumentOutOfRangeException_For_Invalid_Parallelism(int parallelism)
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new PasswordHasher(parallelism: parallelism));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(-1)]
        [InlineData(1)]
        [InlineData(7)]
        public void Constructor_Throws_ArgumentOutOfRangeException_For_Invalid_MemorySize(int memorySize)
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => new PasswordHasher(memorySize: memorySize));
        }

        [Theory]
        [InlineData("")]
        [InlineData(" ")]
        [InlineData(null)]
        public void Verify_Throws_ArgumentNullException_For_Empty_Hash(string hash)
        {
            var target = PasswordHasher.Default;
            var salt = Convert.ToBase64String(new byte[] { 0x1, 0x2 });
            Assert.Throws<ArgumentNullException>(() => target.Verify("password", hash, salt));
        }

        [Theory]
        [InlineData("")]
        [InlineData(" ")]
        [InlineData(null)]
        public void Verify_Throws_ArgumentNullException_For_Empty_Salt(string salt)
        {
            var target = PasswordHasher.Default;
            var hash = Convert.ToBase64String(new byte[] { 0x1, 0x2 });
            Assert.Throws<ArgumentNullException>(() => target.Verify("password", hash, salt));
        }

        [Theory]
        [InlineData("not a base64 string")]
        [InlineData("%aGVsbG8=")]
        [InlineData("aGVsbG8=%")]
        public void Verify_Throws_ArgumentException_For_Invalid_Hash(string hash)
        {
            var target = PasswordHasher.Default;
            var salt = Convert.ToBase64String(new byte[] { 0x1, 0x2 });
            Assert.Throws<ArgumentException>(() => target.Verify("password", hash, salt));
        }

        [Theory]
        [InlineData("not a base64 string")]
        [InlineData("%aGVsbG8=")]
        [InlineData("aGVsbG8=%")]
        public void Verify_Throws_ArgumentException_For_Invalid_Salt(string salt)
        {
            var target = PasswordHasher.Default;
            var hash = Convert.ToBase64String(new byte[] { 0x1, 0x2 });
            Assert.Throws<ArgumentException>(() => target.Verify("password", hash, salt));
        }

        [Theory]
        [InlineData("v")]
        public void PrintHashAndSaltForGivenPassword(string password)
        {
            //TODO: read the encryption keys from an external centrally accessible file
            var encryptionProvider = new AesEncryptionProvider(
                Convert.FromBase64String("OFNL10jziDswqwSzbnXYbw=="),
                Convert.FromBase64String("ehULGl1NuJNuCjXyJHhTnQ=="));

            var secret = Encoding.UTF8.GetBytes("LrTMLM1JNp6ilIoxVN219XmmVMAYlJMoBHR5GvnQ8VLR3ZbZlbjOfrmxd3yggfbJ");
            
            var hasher = new PasswordHasher(knownSecret: secret, encryptionProvider: encryptionProvider);

            hasher.Hash(password, out var hash, out var salt);

            testOutputHelper.WriteLine($"Hash: {hash}");
            testOutputHelper.WriteLine($"Salt: {salt}");
        }
    }
}
