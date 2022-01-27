using System;
using System.Security.Cryptography;
using Xunit;

namespace Password.Hashing.Test
{
    public class AesEncryptionProviderTests
    {
        [Fact]
        public void Can_Serialize_And_Deserialize()
        {
            // arrange
            var data = new byte[] { 0x2, 0x4, 0x8, 0xf };

            var tempKey = Aes.Create();
            var original = new AesEncryptionProvider(tempKey.Key, tempKey.IV);

            var encrypted = original.EncryptBytes(data);

            // act
            var serialized = original.ToXmlString();
            var deserialized = AesEncryptionProvider.FromXmlString(serialized);
            var decrypted = deserialized.DecryptBytes(encrypted);

            // assert
            Assert.Equal(data, decrypted);
        }

        [Fact]
        public void GetSchema_Returns_Null()
        {
            var target = new AesEncryptionProvider();
            Assert.Null(target.GetSchema());
        }

        [Fact]
        public void Throws_ArgumentNullException_If_Key_Null()
        {
            var tempKey = Aes.Create();
            Assert.Throws<ArgumentNullException>(() => new AesEncryptionProvider(null, tempKey.IV));
        }

        [Fact]
        public void Throws_ArgumentNullException_If_IV_Null()
        {
            var tempKey = Aes.Create();
            Assert.Throws<ArgumentNullException>(() => new AesEncryptionProvider(tempKey.Key, null));
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData(" ")]
        public void FromXmlString_Throws_ArgumentNullException_If_Xml_NullEmptyOrWhitespace(string xml)
        {
            Assert.Throws<ArgumentNullException>(() => AesEncryptionProvider.FromXmlString(xml));
        }
    }
}
