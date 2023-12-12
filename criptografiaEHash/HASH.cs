using Org.BouncyCastle.Crypto.Digests;
using System.Security.Cryptography;
using System.Text;
using Blake3;
using System.Diagnostics;
using Sodium;

namespace criptografiaEHash
{
	/// <summary>
	/// Modulo 4 aula 4
	/// </summary>
	internal class HASH
	{
		const string MENSAGEM = "Mensagem";
		public static void Execute()
		{
			Console.WriteLine("Mensagem: {0}", MENSAGEM);

			//Sha3();
			//Sha2();
			//Sha1();
			//Blake3();

			BenchMarkHash();

		}

		/// <summary>
		/// Seguro, sem registros de ataque com sucesso
		/// Evolução do sha2
		/// Mais lento que o Sha2
		/// dotnet não tem suporte nativo, preciso usar a lib Org.BouncyCastle.Crypto.Digests
		/// </summary>
		private static void Sha3()
		{
			Console.WriteLine();
			Console.WriteLine("============= SHA-3 =============");

			var SHA3 = (int bitLenght, string mensagem) =>
			{
				var hashAlgorithm = new Sha3Digest(bitLenght);
				var input = Encoding.UTF8.GetBytes(mensagem);

				hashAlgorithm.BlockUpdate(input, 0, input.Length);
				var result = new byte[bitLenght / 8];
				hashAlgorithm.DoFinal(result, 0);
				return BitConverter.ToString(result).Replace("-", "").ToLowerInvariant();
			};

			Console.WriteLine("SHA3-224: {0}", SHA3(224, MENSAGEM));
			Console.WriteLine("SHA3-256: {0}", SHA3(256, MENSAGEM));
			Console.WriteLine("SHA3-384: {0}", SHA3(384, MENSAGEM));
			Console.WriteLine("SHA3-512: {0}", SHA3(512, MENSAGEM));
		}

		/// <summary>
		/// Seguro, sem registros de ataque com sucesso
		/// </summary>
		private static void Sha2()
		{
			Console.WriteLine();
			Console.WriteLine("============= SHA-2 =============");
			Console.WriteLine("SHA-224: .NET nao oferece suporte nativo ao 224.");
			using (var sha256Hash = SHA256.Create())
			{
				var hash = sha256Hash.ComputeHash(Encoding.ASCII.GetBytes(MENSAGEM));
				Console.WriteLine("SHA-256: {0}", BitConverter.ToString(hash).ToLower().Replace("-", string.Empty));
			}

			using (var sha384Hash = SHA384.Create())
			{
				var hash = sha384Hash.ComputeHash(Encoding.ASCII.GetBytes(MENSAGEM));
				Console.WriteLine("SHA-384: {0}", BitConverter.ToString(hash).ToLower().Replace("-", string.Empty));
			}

			using (var sha512Hash = SHA512.Create())
			{
				var hash = sha512Hash.ComputeHash(Encoding.ASCII.GetBytes(MENSAGEM));
				Console.WriteLine("SHA-512: {0}", BitConverter.ToString(hash).ToLower().Replace("-", string.Empty));
			}


		}
		private static void Sha1()
		{
			Console.WriteLine();
			Console.WriteLine("============= SHA-1 =============");

			using (var sha1 = SHA1.Create())
			{
				var hash = sha1.ComputeHash(Encoding.ASCII.GetBytes(MENSAGEM));
				Console.WriteLine("SHA-1: {0}", BitConverter.ToString(hash).ToLower().Replace("-", string.Empty));
			}
		}

		/// <summary>
		/// 15x mais rapido que o sha 3
		/// não tem suporte nativo usar a lib: Blake3
		/// </summary>
		public static void Blake3()
		{
			Console.WriteLine();
			Console.WriteLine("============= Blake-3 =============");

			var mensagens = new[] { "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z" };

			foreach (var mensagem in mensagens)
			{
				var hash = Hasher.Hash(Encoding.UTF8.GetBytes(mensagem));
				Console.WriteLine("Blake3: {0} - {1}", mensagem, hash);
			}
		}


		/// <summary>
		/// Argon usar a lib Sodium.Core
		/// Algoritimos recomendados para senha em ordem de utilização se a tecnologia não dar suporte
		/// Argon2(Recomendação OWASP)
		///BCrypt
		///Scrypt
		///PBKDF2 com 310.000 iterações e hash HMAC-SHA-256
		/// </summary>

		public static void BenchMarkHash()
		{
			long _time = 20_000;
			double seconds = 0;
			var hashCount = 0;

			var MD5 = (string password, out double totaltime, out int count) =>
			{
				var seconds = Stopwatch.StartNew();
				var hashCount = 0;
				var bytes = Encoding.ASCII.GetBytes(password);
				var md5 = System.Security.Cryptography.MD5.Create();
				do
				{
					md5.ComputeHash(bytes);
					hashCount++;
				} while (seconds.ElapsedMilliseconds < _time);

				seconds.Stop();
				totaltime = seconds.Elapsed.TotalSeconds;
				count = hashCount;
			};

			var Blake = (string password, out double totaltime, out int count) =>
			{
				var seconds = Stopwatch.StartNew();
				var hashCount = 0;
				var bytes = Encoding.ASCII.GetBytes(password);

				do
				{
					Hasher.Hash(bytes);
					hashCount++;
				} while (seconds.ElapsedMilliseconds < _time);

				seconds.Stop();
				totaltime = seconds.Elapsed.TotalSeconds;
				count = hashCount;
			};

			var Sha256 = (string password, out double totaltime, out int count) =>
			{
				var shA256Managed = SHA256.Create();
				var bytes = Encoding.ASCII.GetBytes(password);

				var seconds = Stopwatch.StartNew();
				var hashCount = 0;
				do
				{
					shA256Managed.ComputeHash(bytes);
					hashCount++;
				} while (seconds.ElapsedMilliseconds < _time);

				seconds.Stop();
				totaltime = seconds.Elapsed.TotalSeconds;
				count = hashCount;
			};

			var Argon2 = (string password, out double totaltime, out int count) =>
			{
				var seconds = Stopwatch.StartNew();
				var hashCount = 0;
				do
				{
					PasswordHash.ArgonHashString(password, PasswordHash.StrengthArgon.Moderate);
					hashCount++;
				} while (seconds.ElapsedMilliseconds < _time);

				seconds.Stop();
				totaltime = seconds.Elapsed.TotalSeconds;
				count = hashCount;
			};


			var password = "Sup3rSecr3t";
			Console.WriteLine($"Quantas senhas podem ser hasheadas em 20 segundos?");
			Console.WriteLine();
			Console.WriteLine("========================================");
			Console.WriteLine("            MD5 hashes");
			MD5(password, out seconds, out hashCount);
			Console.WriteLine($"MD5: {hashCount:N}");

			Console.WriteLine();
			Console.WriteLine("========================================");
			Console.WriteLine("            SHA256 hashes");

			Sha256(password, out seconds, out hashCount);
			Console.WriteLine($"SHA256: {hashCount:N}");

			Console.WriteLine();
			Console.WriteLine("========================================");
			Console.WriteLine("            BLAKE hashes");

			Blake(password, out seconds, out hashCount);
			Console.WriteLine($"Blake3: {hashCount:N}");

			Console.WriteLine();
			Console.WriteLine("========================================");
			Console.WriteLine("            Argon2 hashes");

			Argon2(password, out seconds, out hashCount);
			Console.WriteLine($"Argon2: {hashCount:N}");
		}
		
	}
}
