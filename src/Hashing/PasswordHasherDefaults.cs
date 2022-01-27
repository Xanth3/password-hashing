namespace Password.Hashing
{
    /// <summary>
    /// Default values for <see cref="PasswordHasher" />.
    /// </summary>
    public static class PasswordHasherDefaults
    {
        /// <summary>
        /// Default hash size in bytes.
        /// </summary>
        public const int HashSize = 128;

        /// <summary>
        /// Default salt length in bytes.
        /// </summary>
        public const int SaltLength = 128;

        /// <summary>
        /// Default number of iterations.
        /// </summary>
        public const int Iterations = 40;

        /// <summary>
        /// Default degree of parallelism.
        /// </summary>
        public const int Parallelism = 2;

        /// <summary>
        /// Default memory size usage.
        /// </summary>
        public const int MemorySize = 4096;
    }
}
