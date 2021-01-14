using Microsoft.Identity.Client;
using Microsoft.Azure.KeyVault;
//using Azure.Security.KeyVault.Secrets;
using System;
using System.Configuration;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using System.CommandLine;
using System.CommandLine.Invocation;
using System.CommandLine.IO;

namespace KeyVaultClientMsal
{
    public static class Program
    {
        private static string _tenant = ConfigurationManager.AppSettings["ida:TenantId"];
        private static string _client = ConfigurationManager.AppSettings["ida:ClientId"];
        private static string _certThumb = ConfigurationManager.AppSettings["ida:CertThumbprint"];
        private static string _keyVaultName = ConfigurationManager.AppSettings["ida:KeyVaultName"];

        private static string _redirectUri = "http://localhost:1234";

        private static String _secretName;
        private static bool _verbose = false;

        private static KeyVaultClient kvClient;

        private static string[] _scopes = new string[] { "https://vault.azure.net/.default" };

        public static int Main(string[] args)
        {
            var cmd = new RootCommand
            {
                //description: "Gets a secret from Key Vault.",
                new Argument<string>("secret", "Key Vault secret name."),
                new Option<string?>(new[] { "--clientId", "-c" }, "The clientId of the Azure AD App. (GUID)"),
                //new Option<string?>(new[] { "--redirectUri", "-uri" }, "The Redirect URI of the Azure AD App."),
                new Option<string?>(new[] { "--tenantId", "-t" }, "The tenantId of the Azure AD Tenant. (GUID)"),
                new Option<string?>(new[] { "--vaultName", "-vault", "-kv" }, "The name of the Key Vault."),
                new Option<string?>(new[] { "--thumbprint", "-tp", "-cert" }, "The thumbprint of the local certificate."),
                new Option(new[] { "--verbose", "-v" }, "Show verbose details."),
            };

            cmd.Handler = CommandHandler.Create<string, string?, string?, string?, string?, bool, IConsole>(HandleOptions);


            return cmd.Invoke(args);
        }

        static void HandleOptions(string secret, string? clientId, string? tenantId, string? vaultName, string? thumbprint, bool verbose, IConsole console)
        {
            _secretName = secret;
            if (verbose)
            {
                _verbose = true;
                console.Out.WriteLine($"Set to verbose.");
                console.Out.WriteLine($"Secret Name: {_secretName}");

                Console.WriteLine($"---From App.Config---");
                Console.WriteLine($" ClientID: {_client}");
                Console.WriteLine($" TenantID: {_tenant}");
                Console.WriteLine($" Key Vault: {_keyVaultName}");
                Console.WriteLine($" Cert: {_certThumb}");

                Console.WriteLine($"---From Arguments---");
                console.Out.WriteLine($" Arg ClientID: {clientId}");
                console.Out.WriteLine($" Arg TenantID: {tenantId}");
                console.Out.WriteLine($" Arg Key Vault: {vaultName}");
                console.Out.WriteLine($" Arg Cert: {thumbprint}");
            }

            if (!String.IsNullOrEmpty(clientId))
                _client = clientId;
            if (!String.IsNullOrEmpty(tenantId))
                _tenant = tenantId;
            if (!String.IsNullOrEmpty(vaultName))
                _keyVaultName = vaultName;
            if (!String.IsNullOrEmpty(thumbprint))
                _certThumb = thumbprint;

            if (verbose)
            {
                Console.WriteLine($"---Using---");
                console.Out.WriteLine($" ClientID: {_client}");
                console.Out.WriteLine($" TenantID: {_tenant}");
                console.Out.WriteLine($" Key Vault: {_keyVaultName}");
                console.Out.WriteLine($" Cert: {_certThumb}");
            }
            var getResult = GetSecret(_secretName);
            //Console.WriteLine(getResult);
        }

        static async Task<string> GetSecret(string secretName)
        {
            X509Certificate2 cert = ReadCertificateFromStore(_certThumb);
            if (_verbose)
                Console.WriteLine("Found certificate.");
            kvClient = new KeyVaultClient(async (authority, resource, scope) =>
                {
                    IConfidentialClientApplication conClientApp = ConfidentialClientApplicationBuilder
                            .Create(_client)
                            .WithAuthority(AzureCloudInstance.AzurePublic, _tenant)
                            .WithCertificate(cert)
                            .WithRedirectUri(_redirectUri)
                            .Build();

                    AuthenticationResult authenticationResult = await conClientApp
                        .AcquireTokenForClient(_scopes)
                        .ExecuteAsync();
                    if (_verbose)
                    {
                        Console.WriteLine("AccessToken: ");
                        Console.WriteLine($"{authenticationResult.AccessToken}");
                        foreach (string thisScope in authenticationResult.Scopes)
                        {
                            Console.WriteLine($"Scope: {thisScope}");
                        }
                        //Console.WriteLine($"TenantId: {authenticationResult.TenantId}");
                    }
                    return authenticationResult.AccessToken;
                });
            if (_verbose)
                Console.WriteLine("Got key vault client.");

            string secretUri = $"https://{_keyVaultName}.vault.azure.net/secrets/{_secretName}";

            try
            {
                var secretBundle = kvClient.GetSecretAsync(secretUri).Result;

                if (_verbose)
                {
                    Console.WriteLine("Got secretBundle.");
                    Console.WriteLine($" {secretBundle.SecretIdentifier}");
                    Console.WriteLine($" Secret Value: {secretBundle.Value}");
                }
                else
                {
                    Console.WriteLine($"{secretBundle.Value}");
                }
                return secretBundle.Value;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                return null;
            }

        }

        private static X509Certificate2 ReadCertificateFromStore(string certThumb)
        {
            X509Certificate2 cert = null;
            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection certCollection = store.Certificates;

            // Find unexpired certificates.
            X509Certificate2Collection currentCerts = certCollection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);

            // From the collection of unexpired certificates, find the ones with the correct name.
            X509Certificate2Collection signingCert = currentCerts.Find(
                X509FindType.FindByThumbprint, certThumb, false);

            // Return the first certificate in the collection, has the right name and is current.
            cert = signingCert.OfType<X509Certificate2>().OrderByDescending(c => c.NotBefore).FirstOrDefault();
            store.Close();
            return cert;
        }

    }
}
