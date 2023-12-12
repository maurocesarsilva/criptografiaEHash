using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace criptografiaEHash
{
	internal class Mac
	{
		public static void Execute()
		{
			var mensagem = "desenvolvedorio";
			Console.WriteLine("Mensagem: {0}", mensagem);

			byte[] chave = new byte[16];
			RandomNumberGenerator.Fill(chave);
			var hmac = new HMACSHA256(chave);
			var hmacResult = hmac.ComputeHash(Encoding.ASCII.GetBytes(mensagem));

			Console.WriteLine("Senha: {0}", BitConverter.ToString(chave).ToLower().Replace("-", string.Empty));
			Console.WriteLine("HMAC-SHA-256: {0}", BitConverter.ToString(hmacResult).ToLower().Replace("-", string.Empty));
		}
	}
}
