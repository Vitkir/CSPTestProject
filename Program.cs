using CryptoPro.Sharpei;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace CSPTestProject
{
	class Program
	{

		static void Main(string[] args)
		{
			string sertPublisherName = "CRYPTO-PRO Test Center 2";
			string sourceDataFile = @"C:\Users\кирилл\Downloads\data.txt";
			string encDataFile = @"C:\Users\кирилл\Downloads\encData.txt";
			string decDataFile = @"C:\Users\кирилл\Downloads\decData.txt";
			var sertByBytes = ReadFile(@"C:\Users\кирилл\Downloads\KirillTestSert.cer");
			try
			{
				var certificate = GetSert(sertPublisherName)[0];

				Console.WriteLine(File.ReadAllText(sourceDataFile));
				Console.WriteLine();

				EncriptFile(certificate, sourceDataFile, encDataFile);
				Console.WriteLine();
				Console.WriteLine(File.ReadAllText(encDataFile));
				Console.WriteLine();

				DecriptFile(sertPublisherName, encDataFile, decDataFile);
				Console.WriteLine();
				Console.WriteLine(File.ReadAllText(decDataFile));
			}
			catch (ArgumentNullException e)
			{
				Console.WriteLine(e.Message);
			}
		}

		#region Encription

		private static void EncriptFile(X509Certificate2 sert, string sourceFile, string encFile)
		{
			var publicKey = (Gost3410_2012_256CryptoServiceProvider)sert.PublicKey.Key;

			var asymmetricAlg = publicKey as Gost3410_2012_256;

			if (asymmetricAlg == null)
				throw new CryptographicException("Not a gost certificate");

			var symmetricKey = Gost28147.Create();

			Gost3410_2012_256 senderRndKey = Gost3410_2012_256.Create();
			Gost3410Parameters senderRndKeyParameters = senderRndKey.ExportParameters(false);

			GostSharedSecretAlgorithm agreeKey = senderRndKey.CreateAgree(asymmetricAlg.ExportParameters(false));

			var encodedSymmetricKey = agreeKey.Wrap(symmetricKey, GostKeyWrapMethod.CryptoProKeyWrap);

			ICryptoTransform transform = symmetricKey.CreateEncryptor();

			using (FileStream writer = new FileStream(encFile, FileMode.Create))
			{
				BinaryWriter binaryWriter = new BinaryWriter(writer);

				binaryWriter.Write(encodedSymmetricKey.Length);
				binaryWriter.Write(encodedSymmetricKey);

				binaryWriter.Write(symmetricKey.IV.Length);
				binaryWriter.Write(symmetricKey.IV);

				BinaryFormatter binaryFormatter = new BinaryFormatter();
				binaryFormatter.Serialize(writer, senderRndKeyParameters);

				using (CryptoStream cryptoStream = new CryptoStream(writer, transform, CryptoStreamMode.Write))
				{
					var buffer = new byte[100];

					using (FileStream reader = new FileStream(sourceFile, FileMode.Open, FileAccess.Read))
					{
						var length = reader.Read(buffer, 0, buffer.Length);
						while (length > 0)
						{
							cryptoStream.Write(buffer, 0, buffer.Length);
							length = reader.Read(buffer, 0, buffer.Length);
						}
					}
				}
			}
		}

		private static void DecriptFile(string sertPublisherName, string encDataFile, string decDataFile)
		{
			var sert = GetSert(sertPublisherName)[0];

			var provider = (Gost3410_2012_256CryptoServiceProvider)sert.PrivateKey;

			using (FileStream reader = new FileStream(encDataFile, FileMode.Open, FileAccess.Read))
			{
				BinaryReader binaryReader = new BinaryReader(reader);

				byte[] simKeyByData;
				var symKeyLen = binaryReader.ReadInt32();
				simKeyByData = binaryReader.ReadBytes(symKeyLen);

				byte[] ivByData;
				var ivLen = binaryReader.ReadInt32();
				ivByData = binaryReader.ReadBytes(ivLen);

				BinaryFormatter binaryFormatter = new BinaryFormatter();
				var senderRndKeyParameters = (Gost3410Parameters)binaryFormatter.Deserialize(reader);

				GostSharedSecretAlgorithm agreeKey = provider.CreateAgree(senderRndKeyParameters);

				var sessionKey = agreeKey.Unwrap(simKeyByData, GostKeyWrapMethod.CryptoProKeyWrap);

				ICryptoTransform transform = sessionKey.CreateDecryptor();

				using (CryptoStream cryptoStream = new CryptoStream(reader, transform, CryptoStreamMode.Read))
				{
					var buffer = new byte[100];

					using (FileStream writer = new FileStream(decDataFile, FileMode.Create))
					{
						var length = cryptoStream.Read(buffer, 0, buffer.Length);
						while (length > 0)
						{
							writer.Write(buffer, 0, buffer.Length);
							length = reader.Read(buffer, 0, buffer.Length);
						}
					}
				}
			}
		}

		#endregion

		private static void VerifySignedData(string sertPublisherName)
		{
			try
			{
				X509Certificate2Collection x509Certificate2 = GetSert(sertPublisherName);

				var sert = x509Certificate2[0];

				var cspSender = (Gost3410_2012_256CryptoServiceProvider)sert.PrivateKey;

				var cspRecipient = (Gost3410_2012_256CryptoServiceProvider)sert.PublicKey.Key;

				var dataFromFile = ReadFile(@"C:\Users\кирилл\Downloads\data.txt");

				var signFromFile = ReadFile(@"C:\Users\кирилл\Downloads\sign.txt");


				Gost3411_2012_256CryptoServiceProvider GostHash = new Gost3411_2012_256CryptoServiceProvider();

				var dataHash = GostHash.ComputeHash(dataFromFile);


				bool b = cspRecipient.VerifyData(dataFromFile, GostHash, signFromFile);

				if (b)
				{
					Console.WriteLine("подпись вычислена верно.");
				}
				else
				{
					Console.WriteLine("подпись вычислена неверно.");
				}
			}
			catch (ArgumentNullException e)
			{
				Console.WriteLine(e.Message);
			}
		}

		private static X509Certificate2Collection GetSert(string publisherName)
		{
			X509Store x509Store = new X509Store(StoreName.My, StoreLocation.CurrentUser);

			x509Store.Open(OpenFlags.ReadOnly);

			X509Certificate2Collection collection = x509Store.Certificates;

			return collection.Find(X509FindType.FindByIssuerName, publisherName, false);
		}

		public static void WriteSignToFile(string path, byte[] sign)
		{
			File.WriteAllBytes(path, sign);
		}

		public static byte[] ReadFile(string path)
		{
			return File.ReadAllBytes(path);
		}
	}
}
