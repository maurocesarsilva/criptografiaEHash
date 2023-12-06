using System.Security.Cryptography;
using System.Text;

namespace criptografiaEHash
{
	internal class AES
	{
		/// <summary>
		/// Menos segura
		/// </summary>
		public static void CBCExecute()
		{
			Console.WriteLine("============== CRIPTOGRAFANDO CBC ==============");
			var mensagem = "MENSAGEM";
			RandomNumberGenerator random = RandomNumberGenerator.Create();
			byte[] chave = new byte[16];

			//Initialization vector
			//precisa ser do mesmo tamanho da chave
			byte[] iv = new byte[16];

			random.GetBytes(chave);
			random.GetBytes(iv);

			Aes aes = Aes.Create();
			aes.Key = chave;
			aes.IV = iv;
			var ciphertext = aes.EncryptCbc(Encoding.UTF8.GetBytes(mensagem), iv, PaddingMode.PKCS7);

			Console.WriteLine("Mensagem: {0}", mensagem);
			Console.WriteLine("Senha: {0}", Convert.ToHexString(chave));
			Console.WriteLine("Cipher: {0}", Convert.ToHexString(ciphertext));
			Console.WriteLine();

			Console.WriteLine("============== DESCRIPTOGRAFANDO ==============");

			
			Console.WriteLine(Encoding.UTF8.GetString(aes.DecryptCbc(ciphertext, iv, PaddingMode.PKCS7)));
		}


		/// <summary>
		/// Mais segura
		/// </summary>
		public static void GCMExecute()
		{
			// variaveis
			string mensagem = "MENSAGEM";
			byte[] chave = new byte[16];

			//precisa saber o initializationVector e o authTag para decriptar
			byte[] initializationVector = new byte[12];
			byte[] authTag = new byte[16];

			// Gera a chave e o iv
			RandomNumberGenerator.Fill(chave);
			RandomNumberGenerator.Fill(initializationVector);

			// Exibe as informacoes na tela
			Console.WriteLine("============== CRIPTOGRAFANDO ==============");
			Console.WriteLine("mensagem: {0}", mensagem);
			WriteByteArray("chave", chave);
			Console.WriteLine();

			// converte a mensagem para bytes
			byte[] plainBytes = Encoding.UTF8.GetBytes(mensagem);
			byte[] cipher = new byte[plainBytes.Length];

			// Criptografia
			using (var aesgcm = new AesGcm(chave))
				aesgcm.Encrypt(initializationVector, plainBytes, cipher, authTag);

			WriteByteArray("cipher", cipher);
			WriteByteArray("iv", initializationVector);
			WriteByteArray("authTag", authTag);

			Console.WriteLine();

			Console.WriteLine("============== DESCRIPTOGRAFANDO ==============");
			// Transforma em base64 para poder transmitir
			Console.WriteLine("cipher: {0}", Convert.ToBase64String(cipher));
			Console.WriteLine("iv: {0}", Convert.ToBase64String(initializationVector));
			Console.WriteLine("authTag: {0}", Convert.ToBase64String(authTag));

			Console.WriteLine();
			// allocate the decrypted text byte array as the same size as the plain text byte array
			byte[] decryptedBytes = new byte[cipher.Length];
			// perform decryption
			using (AesGcm aesgcm = new AesGcm(chave))
				aesgcm.Decrypt(initializationVector, cipher, authTag, decryptedBytes);

			// convert the byte array to the plain text string
			string decryptedText = Encoding.UTF8.GetString(decryptedBytes);
			Console.WriteLine("mensagem: {0}", decryptedText);
			Console.WriteLine();
		}

		private static void WriteByteArray(string name, byte[] byteArray)
		{
			Console.Write("{0}: {1} bytes, {2}-bit:", name, byteArray.Length, byteArray.Length << 3);
			Console.WriteLine(" -> {0} - base64: {1}", BitConverter.ToString(byteArray), Convert.ToBase64String(byteArray));
		}

	}
}
