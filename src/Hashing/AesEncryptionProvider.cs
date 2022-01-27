using System;
using System.IO;
using System.Security.Cryptography;
using System.Xml;
using System.Xml.Schema;
using System.Xml.Serialization;

namespace Password.Hashing
{
    /// <summary>
    /// Implementation of <see cref="IEncryptionProvider" /> using AES.
    /// </summary>
    public sealed class AesEncryptionProvider : IEncryptionProvider, IXmlSerializable
    {
        private static readonly XmlSerializer Serializer = new XmlSerializer(typeof(AesEncryptionProvider));

        private byte[] _key;
        private byte[] _iv;

        /// <summary>
        /// Initializes a new instance of the <see cref="AesEncryptionProvider" /> class.
        /// </summary>
        public AesEncryptionProvider()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AesEncryptionProvider" /> class.
        /// </summary>
        /// <param name="key">Secret key</param>
        /// <param name="iv">Initialization vector</param>
        /// <exception cref="ArgumentNullException">Key cannot be null</exception>
        /// <exception cref="ArgumentNullException">IV cannot be null</exception>
        public AesEncryptionProvider(byte[] key, byte[] iv)
        {
            _key = key ?? throw new ArgumentNullException(nameof(key), "Key cannot be null");
            _iv = iv ?? throw new ArgumentNullException(nameof(iv), "IV cannot be null");
        }

        /// <inheritdoc />
        public XmlSchema GetSchema() => null;

        /// <inheritdoc />
        public void ReadXml(XmlReader reader)
        {
            while (reader.Read())
            {
                if (reader.NodeType == XmlNodeType.Element)
                {
                    if (reader.Name == "key")
                    {
                        _key = Convert.FromBase64String(reader.ReadElementContentAsString());
                    }

                    if (reader.Name == "iv")
                    {
                        _iv = Convert.FromBase64String(reader.ReadElementContentAsString());
                    }
                }
            }
        }

        /// <inheritdoc />
        public void WriteXml(XmlWriter writer)
        {
            writer.WriteStartElement("key");
            writer.WriteValue(Convert.ToBase64String(_key));
            writer.WriteEndElement();

            writer.WriteStartElement("iv");
            writer.WriteValue(Convert.ToBase64String(_iv));
            writer.WriteEndElement();
        }

        /// <inheritdoc />
        public byte[] EncryptBytes(byte[] bytes)
        {
            byte[] encrypted;

            using (var aes = CreateAes())
            {
                var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        cs.Write(bytes, 0, bytes.Length);
                    }

                    encrypted = ms.ToArray();
                }
            }

            return encrypted;
        }

        /// <inheritdoc />
        public byte[] DecryptBytes(byte[] bytes)
        {
            byte[] decrypted;

            using (var aes = CreateAes())
            {
                var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Write))
                    {
                        cs.Write(bytes, 0, bytes.Length);
                    }

                    decrypted = ms.ToArray();
                }
            }

            return decrypted;
        }

        /// <summary>
        /// Serializes these parameters to an XML string.
        /// </summary>
        /// <returns>A serialized version of these parameters as an XML string</returns>
        public string ToXmlString()
        {
            using (var sww = new StringWriter())
            {
                using (var writer = XmlWriter.Create(sww))
                {
                    Serializer.Serialize(writer, this);
                    return sww.ToString();
                }
            }
        }

        /// <summary>
        /// Parses an XML string to read out a new instance of <see cref="AesEncryptionProvider" />.
        /// </summary>
        /// <param name="xml">XML string to parse</param>
        /// <returns>A parsed <see cref="AesEncryptionProvider" /> object.</returns>
        /// <exception cref="ArgumentNullException">XML string cannot be null</exception>
        public static AesEncryptionProvider FromXmlString(string xml)
        {
            if (string.IsNullOrWhiteSpace(xml))
            {
                throw new ArgumentNullException(nameof(xml), "XML string cannot be null");
            }

            using (var reader = new StringReader(xml))
            {
                return Serializer.Deserialize(reader) as AesEncryptionProvider;
            }
        }

        private Aes CreateAes()
        {
            var aes = Aes.Create();

            if (_key != null)
            {
                aes.Key = _key;
            }

            if (_iv != null)
            {
                aes.IV = _iv;
            }

            return aes;
        }
    }
}
