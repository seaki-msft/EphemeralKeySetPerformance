using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace EphemeralKeySetPerformance
{
    class Program
    {
        static async Task Main(string[] args)
        {
            var kvClient = new SecretClient(new Uri("https://integrationtests.vault.azure.net/"), new VisualStudioCredential());
            var secretResponse = await kvClient.GetSecretAsync("Apihub-Common-Cert-DataEncryption2", "bf73594f9f974f1fa7f0dc2fbf8bf792");
            var secretResponse2 = await kvClient.GetSecretAsync("Apihub-Common-Cert-DataEncryption2", "17d45bc373764bc781a6155ce557cd84");
            var bytes = Convert.FromBase64String(secretResponse.Value.Value);
            var bytes2 = Convert.FromBase64String(secretResponse2.Value.Value);

            CheckDecryptPerformance(bytes, useEphemeral: false, useNewDecryption: false);
            CheckDecryptPerformance(bytes, useEphemeral: false, useNewDecryption: true);
            CheckDecryptPerformance(bytes, useEphemeral: true, useNewDecryption: true);
        }

        private static string CheckDecryptPerformance(byte[] certBytes, bool useEphemeral, bool useNewDecryption)
        {
            var cert = useEphemeral ? InitializeUsingEphemeral(certBytes) : InitializeUsingBytesDirectly(certBytes);

            Stopwatch sw = new Stopwatch();
            sw.Start();
            for (var idx = 0; idx < 1000; idx++)
            {
                DecryptData(cert, useNewDecryption);
            }
            sw.Stop();
            var message = $"useEphemeral={useEphemeral}, useNewDecrpytion={useNewDecryption}, Elapsed={sw.Elapsed}";
            Console.WriteLine(message);
            return message;
        }

        private static void DecryptData(X509Certificate2 cert, bool useNewDecryption)
        {
            byte[] encrypted = Convert.FromBase64String("SEAXxi6efQwjuTK9sYnZsyAieWi4QdnEUw1STTpRzBRpdSlqsNUGLRIg6VT7qtONeOZ52nNCjKVygj9HO9mctW/kSfoFnAZUITC9wg1B6NWPKk88kUT+HL6vI6th55LlqC4+clGqFrUm8CkqYknTF4w/W7ZrPqcRQ21IvLI1o3ESZ1TCRyK3fax58DHzpddbs4MdzjUmYlWGMW8i/BzMr1juBwcTMM9M8D+P5E4cboSsMiKh6ikPCBjEc4w472gqLtQLD/c1n39ERFOcmBf3HB7UVh/HOT5tE0ZX0hm2VFj1VChPEossXNB56AY0g4sNGWi1TxxYOaMrbDwtNsCZqQ==");

            if (useNewDecryption)
            {
                byte[] rgbKey = cert.GetRSAPrivateKey().Decrypt(encrypted, RSAEncryptionPadding.OaepSHA256);
            }
            else
            {
                byte[] rgbKey = ((RSACryptoServiceProvider)cert.PrivateKey).Decrypt(encrypted, true);
            }
        }

        public static X509Certificate2 InitializeUsingBytesDirectly(byte[] bytes, string password = null)
        {
            try
            {
                X509Certificate2 cert = new X509Certificate2(bytes, password, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.UserKeySet);
                return cert;
            }
            catch (Exception exception)
            {
                throw;
            }
        }

        // Initialize the certificate using memory only and does not create a private key file. 
        // This reduces a chance of error when the private key file is not properly managed. 
        public static X509Certificate2 InitializeUsingEphemeral(byte[] bytes, string password = null)
        {
            try
            {
                var inmem = new InMemoryX509Certificate(bytes, password);
                var cert = new X509Certificate2(inmem.Handle);
                return cert;
            }
            catch (Exception exception)
            {
                throw;
            }
        }
    }
}
