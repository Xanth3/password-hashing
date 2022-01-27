namespace Password.Hashing
{
    /// <summary>
    /// Provides a common abstraction for encryption methods for use in <see cref="PasswordHasher" />.
    /// </summary>
    public interface IEncryptionProvider
    {
        /// <summary>
        /// Encrypts a given byte array and returns the result.
        /// </summary>
        /// <param name="bytes">Data to encrypt</param>
        /// <returns>The encrypted bytes produced from <paramref name="bytes"/>.</returns>
        byte[] EncryptBytes(byte[] bytes);

        /// <summary>
        /// Decrypts a given byte array and returns the result.
        /// </summary>
        /// <param name="bytes">Data to decrypt</param>
        /// <returns>The decrypted bytes produced from <paramref name="bytes"/>.</returns>
        byte[] DecryptBytes(byte[] bytes);
    }
}
