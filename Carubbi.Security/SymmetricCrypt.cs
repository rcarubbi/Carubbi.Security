using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Carubbi.Security
{
    /// <summary>
    /// Implementação de criptografia Simétrica
    /// </summary>
    public class SymmetricCrypt
    {
        #region Variáveis e Métodos Privados

        private readonly SymmetricCryptProvider _cryptProvider;
        private readonly SymmetricAlgorithm _algorithm;

        /// <summary>
        /// Inicialização do vetor do algoritmo simétrico
        /// </summary>
        private void SetIV() => _algorithm.IV = _cryptProvider == SymmetricCryptProvider.Rijndael
                ? (new byte[]
                    {0xf, 0x6f, 0x13, 0x2e, 0x35, 0xc2, 0xcd, 0xf9, 0x5, 0x46, 0x9c, 0xea, 0xa8, 0x4b, 0x73, 0xcc})
                : (new byte[] { 0xf, 0x6f, 0x13, 0x2e, 0x35, 0xc2, 0xcd, 0xf9 });

        #endregion

        #region Properties
        /// <summary>
        /// Chave secreta para o algoritmo simétrico de criptografia.
        /// </summary>
        public string Key { get; set; } = string.Empty;

        #endregion

        #region Constructors
        /// <summary>
        /// Contrutor padrão da classe, é setado um tipo de criptografia padrão (Rijndael).
        /// </summary>
        public SymmetricCrypt()
        {
            _algorithm = new RijndaelManaged { Mode = CipherMode.CBC };
            _cryptProvider = SymmetricCryptProvider.Rijndael;
        }
        /// <summary>
        /// Construtor com o tipo de criptografia a ser usada Você pode escolher o tipo pelo Enum chamado CryptProvider.
        /// </summary>
        /// <param name="cryptProvider">Tipo de criptografia.</param>
        public SymmetricCrypt(SymmetricCryptProvider cryptProvider)
        {
            // Seleciona algoritmo simétrico
            switch (cryptProvider)
            {
                case SymmetricCryptProvider.Rijndael:
                    _algorithm = new RijndaelManaged();
                    _cryptProvider = SymmetricCryptProvider.Rijndael;
                    break;
                case SymmetricCryptProvider.RC2:
                    _algorithm = new RC2CryptoServiceProvider();
                    _cryptProvider = SymmetricCryptProvider.RC2;
                    break;
                case SymmetricCryptProvider.DES:
                    _algorithm = new DESCryptoServiceProvider();
                    _cryptProvider = SymmetricCryptProvider.DES;
                    break;
                case SymmetricCryptProvider.TripleDES:
                    _algorithm = new TripleDESCryptoServiceProvider();
                    _cryptProvider = SymmetricCryptProvider.TripleDES;
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(cryptProvider), cryptProvider, null);
            }

            _algorithm.Mode = CipherMode.CBC;
        }
        #endregion

        #region Public methods
        /// <summary>
        /// Gera a chave de criptografia válida dentro do array.
        /// </summary>
        /// <returns>Chave com array de bytes.</returns>
        public virtual byte[] GetKey()
        {
            var salt = string.Empty;
            // Ajusta o tamanho da chave se necessário e retorna uma chave válida
            if (_algorithm.LegalKeySizes.Length > 0)
            {
                // Tamanho das chaves em bits
                var keySize = Key.Length * 8;
                var minSize = _algorithm.LegalKeySizes[0].MinSize;
                var maxSize = _algorithm.LegalKeySizes[0].MaxSize;
                var skipSize = _algorithm.LegalKeySizes[0].SkipSize;
                if (keySize > maxSize)
                {
                    // Busca o valor máximo da chave
                    Key = Key.Substring(0, maxSize / 8);
                }
                else if (keySize < maxSize)
                {
                    // Seta um tamanho válido
                    var validSize = (keySize <= minSize) ? minSize : keySize - (keySize % skipSize) + skipSize;
                    if (keySize < validSize)
                    {
                        // Preenche a chave com arterisco para corrigir o tamanho
                        Key = Key.PadRight(validSize / 8, '*');
                    }
                }
            }

            var key = new PasswordDeriveBytes(Key, Encoding.ASCII.GetBytes(salt));
            return key.GetBytes(Key.Length);
        }
        /// <summary>
        /// Encripta o dado solicitado.
        /// </summary>
        /// <param name="plainText">Texto a ser criptografado.</param>
        /// <returns>Texto criptografado.</returns>
        public virtual string Encrypt(string texto)
        {
            var plainByte = Encoding.UTF8.GetBytes(texto);
            var keyByte = GetKey();
            // Seta a chave privada
            _algorithm.Key = keyByte;
            SetIV();
            // Interface de criptografia / Cria objeto de criptografia
            ICryptoTransform cryptoTransform = _algorithm.CreateEncryptor();
            var memoryStream = new MemoryStream();
            var cryptoStream = new CryptoStream(memoryStream, cryptoTransform, CryptoStreamMode.Write);
            // Grava os dados criptografados no MemoryStream
            cryptoStream.Write(plainByte, 0, plainByte.Length);
            cryptoStream.FlushFinalBlock();
            // Busca o tamanho dos bytes encriptados
            var cryptoByte = memoryStream.ToArray();
            // Converte para a base 64 string para uso posterior em um xml
            return Convert.ToBase64String(cryptoByte, 0, cryptoByte.GetLength(0));
        }
        /// <summary>
        /// Desencripta o dado solicitado.
        /// </summary>
        /// <param name="encryptedText">Texto a ser descriptografado.</param>
        /// <returns>Texto descriptografado.</returns>
        public virtual string Decrypt(string encryptedText)
        {
            // Converte a base 64 string em num array de bytes
            var cryptoByte = Convert.FromBase64String(encryptedText);
            var keyByte = GetKey();
            // Seta a chave privada
            _algorithm.Key = keyByte;
            SetIV();
            // Interface de criptografia / Cria objeto de descriptografia
            ICryptoTransform cryptoTransform = _algorithm.CreateDecryptor();
            try
            {
                var _memoryStream = new MemoryStream(cryptoByte, 0, cryptoByte.Length);
                var _cryptoStream = new CryptoStream(_memoryStream, cryptoTransform, CryptoStreamMode.Read);
                // Busca resultado do CryptoStream
                var _streamReader = new StreamReader(_cryptoStream);
                return _streamReader.ReadToEnd();
            }
            catch
            {
                return null;
            }
        }
        #endregion
    }
}

