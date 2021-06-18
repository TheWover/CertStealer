using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CommandLine;

public class Program
{

    public class Options
    {
        [Option('i', "import", Required = false, HelpText = "Import a serialized cert.")]
        public bool Import { get; set; }

        [Option('e', "export", Required = false, HelpText = "Export a serialized cert by its thumbprint.")]
        public bool Export { get; set; }

        [Option('l', "list", Required = false, HelpText = "Lists all certs, their details, and prints them in their serialized form.")]
        public bool List { get; set; }

        [Option('s', "store", Required = false, HelpText = "Confines a list to a specified store.")]
        public string Store { get; set; }

        [Option('n', "name", Required = false, HelpText = "Confines a list to a specified location.")]
        public string Location { get; set; }

        [Option('v', "verbose", Required = false, HelpText = "Verbose output.")]
        public bool Verbose { get; set; }

        [Option('h', "help", Required = false, Default = true, HelpText = "Display help message.")]
        public bool HelpMessage { get; set; }
    }

    static void Main(string[] args)
    {
        Parser.Default.ParseArguments<Options>(args)
                   .WithParsed<Options>(o =>
                   {
                       if (o.List)
                       {
                           string location = "";
                           string store = "";

                           if (!String.IsNullOrEmpty(o.Store))
                               store = o.Store;

                           if (!String.IsNullOrEmpty(o.Location))
                               location = o.Location;

                           List(o.Verbose, location, store);
                       }
                       else if (o.Export)
                       {
                           string type = "serialized";
                           string thumbprint = "";
                           if (args.Length >= 2)
                           {
                               if (args.Length >= 3)
                                   type = args[args.Length - 2];
                               thumbprint = args[args.Length - 1];

                               DisplayCertificate(thumbprint, true);

                               switch (type)
                               {
                                   case "serialized":
                                       Export(thumbprint, X509ContentType.SerializedCert);
                                       break;
                                   case "pfx":
                                       Export(thumbprint, X509ContentType.Pfx);
                                       break;
                               }

                           }
                       }
                       else if (o.Import)
                       {
                           string cert = "";
                           string storename = "My";
                           string location = "local";

                            if (args.Length >= 3)
                           {
                               cert = args[args.Length - 1];
                               location = args[args.Length - 2];
                               storename = args[args.Length - 3];

                               switch (location)
                               {
                                   case "local":
                                       Import(cert, storename, StoreLocation.LocalMachine, o.Verbose);
                                       break;
                                   case "user":
                                       Import(cert, storename, StoreLocation.CurrentUser, o.Verbose);
                                       break;
                               }
                           }  
                       }
                       else if (o.HelpMessage)
                           Help();
                   });
    }

    public static void List(bool verbose = false, string location = "", string name = "")
    {
        Console.WriteLine("\r\nExisting Certs Name and Location");
        Console.WriteLine("------ ----- -------------------------");

        StoreLocation loc = StoreLocation.LocalMachine;
        if (!String.IsNullOrEmpty(location))
        {
            switch (location)
            {
                case "local":
                    loc = StoreLocation.LocalMachine;
                    break;
                case "user":
                    loc = StoreLocation.CurrentUser;
                    break;
            }
        }

        foreach (StoreLocation storeLocation in (StoreLocation[])
            Enum.GetValues(typeof(StoreLocation)))
        {
            if (!String.IsNullOrEmpty(location) && storeLocation != loc)
                continue;

            foreach (StoreName storeName in (StoreName[])
                Enum.GetValues(typeof(StoreName)))
            {
                X509Store store = new X509Store(storeName, storeLocation);

                if (!String.IsNullOrEmpty(name) && store.Name != name)
                    continue;

                try
                {
                    store.Open(OpenFlags.OpenExistingOnly);

                    Console.WriteLine("Yes    {0,4}  {1}, {2}",
                        store.Certificates.Count, store.Name, store.Location);
                }
                catch (CryptographicException)
                {
                    Console.WriteLine("No           {0}, {1}",
                        store.Name, store.Location);
                }
            }
            Console.WriteLine();
        }

        Console.WriteLine("\r\nAll Certificate Details");
        Console.WriteLine("------ ----- -------------------------");

        foreach (StoreLocation storeLocation in (StoreLocation[])
            Enum.GetValues(typeof(StoreLocation)))
        {

            if (!String.IsNullOrEmpty(location) && storeLocation != loc)
                continue;

            foreach (StoreName storeName in (StoreName[])
                Enum.GetValues(typeof(StoreName)))
            {
                X509Store store = new X509Store(storeName, storeLocation);

                if (!String.IsNullOrEmpty(name) && store.Name != name)
                    continue;

                try
                {
                    store.Open(OpenFlags.OpenExistingOnly);

                    // Print the certificate details
                    foreach (X509Certificate2 certificate in (store.Certificates))
                        DisplayCertificate(certificate, verbose);
                }
                catch (CryptographicException ex)
                {
                    Console.WriteLine("Failed to export           {0}, {1} for cryptographic error.",
                        store.Name, store.Location);

                    Console.WriteLine("Error message: ");
                    Console.WriteLine(ex.Message);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Failed to import           {0}, {1} due to unknown error.",
                        store.Name, store.Location);

                    Console.WriteLine("Error message: ");
                    Console.WriteLine(ex.Message);
                }
            }
            Console.WriteLine();
        }
    }

    public static void DisplayCertificate(string thumbprint, bool verbose = false)
    {
        foreach (StoreLocation storeLocation in (StoreLocation[])
            Enum.GetValues(typeof(StoreLocation)))
        {
            foreach (StoreName storeName in (StoreName[])
                Enum.GetValues(typeof(StoreName)))
            {
                X509Store store = new X509Store(storeName, storeLocation);

                try
                {
                    store.Open(OpenFlags.OpenExistingOnly);

                    foreach (X509Certificate2 certificate in (store.Certificates))
                    {
                        if (certificate.GetCertHashString() == thumbprint)
                        {
                            try
                            {
                                DisplayCertificate(certificate, verbose);
                            }
                            catch (CryptographicException ex)
                            {
                                Console.WriteLine("Failed to export           {0}, {1} for cryptographic error.",
                                    store.Name, store.Location);

                                Console.WriteLine("Error message: ");
                                Console.WriteLine(ex.Message);

                                //return false; --> We should continue to search for other stores
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine("Failed to export           {0}, {1} due to unknown error.",
                                    store.Name, store.Location);

                                Console.WriteLine("Error message: ");
                                Console.WriteLine(ex.Message);

                                //return false; --> We should continue to search for other stores
                            }
                            
                            break;
                        }

                    }
                }
                catch(Exception ex)
                {
                    // do nothing if it just couldn't open a store or find it
                }
            }


        }
    }

    public static void DisplayCertificate(X509Certificate2 certificate, bool verbose = false)
    {
        Console.WriteLine("----------------------------------");
        Console.WriteLine("Details:");
        Console.WriteLine();

        Console.WriteLine("[Subject]\n\t" + certificate.Subject);
        Console.WriteLine();

        if (verbose)
        {
            Console.WriteLine("[Subject Distinguished Name]\n\t" + certificate.SubjectName.Name);
            Console.WriteLine();
        }

        if (verbose)
        {
            Console.WriteLine("[Friendly Name]\n\t" + certificate.FriendlyName);
            Console.WriteLine();
        }

        if (verbose)
        {
            Console.WriteLine("[Archived]\n\t" + certificate.Archived);
            Console.WriteLine();
        }


        Console.WriteLine("[Has Private Key]\n\t" + certificate.HasPrivateKey);
        Console.WriteLine();

        Console.WriteLine("[Version]\n\t" + certificate.Version);
        Console.WriteLine();

        Console.WriteLine("[Issuer]\n\t" + certificate.Issuer);
        Console.WriteLine();

        if (verbose)
        {
            Console.WriteLine("[Issuer Distinguished Name]\n\t" + certificate.IssuerName.Name);
            Console.WriteLine();
        }

        Console.WriteLine("[Serial Number]\n\t" + certificate.SerialNumber);
        Console.WriteLine();

        Console.WriteLine("[Not Before]\n\t" + certificate.NotBefore);
        Console.WriteLine();

        Console.WriteLine("[Not After]\n\t" + certificate.NotAfter);
        Console.WriteLine();

        Console.WriteLine("[Thumbprint]\n\t" + certificate.Thumbprint);
        Console.WriteLine();

        if (verbose)
        {
            Console.WriteLine("[Serial Number]\n\t" + certificate.SerialNumber);
            Console.WriteLine();

            Console.WriteLine("[Signature Algorithm]\n\t" + certificate.SignatureAlgorithm.Value);
            Console.WriteLine();

            Console.WriteLine("[Signature Algorithm Friendly Name]\n\t" + certificate.SignatureAlgorithm.FriendlyName);
            Console.WriteLine();

            Console.WriteLine("[Public Key]\n\t" + certificate.GetPublicKeyString());
            Console.WriteLine();

            if (certificate.HasPrivateKey)
            {
                Console.WriteLine("[Private Key]");
                try
                {
                    Console.WriteLine("\t" + certificate.PrivateKey.ToXmlString(true));
                    Console.WriteLine();
                }
                catch (CryptographicException ex)
                {
                    Console.WriteLine("\t" + "Error: Could not export private key!");
                    Console.WriteLine("\t" + "Error Mesage: {0}", ex.Message);
                }

            }

            Console.WriteLine("[Key Algorithm]\n\t" + certificate.GetKeyAlgorithm());
            Console.WriteLine();

            Console.WriteLine("[Key Algorithm Parameters]\n\t" + certificate.GetKeyAlgorithmParametersString());
            Console.WriteLine();

            Console.WriteLine("[Verified]\n\t" + certificate.Verify());
            Console.WriteLine();

            Console.WriteLine("Extensions:");
            Console.WriteLine();

            foreach (X509Extension extension in certificate.Extensions)
            {
                if (extension.Oid.FriendlyName == "Enhanced Key Usage")
                {
                    X509EnhancedKeyUsageExtension ext = (X509EnhancedKeyUsageExtension)extension;
                    OidCollection oids = ext.EnhancedKeyUsages;
                    foreach (Oid oid in oids)
                    {
                        Console.WriteLine("\t[Friendly Name]\n\t\t" + oid.FriendlyName);
                        Console.WriteLine();

                        Console.WriteLine("\t[OID]\n\t\t" + oid.Value);
                        Console.WriteLine();
                    }
                }
                else if (extension.Oid.FriendlyName == "Subject Alternative Name")
                {
                    Console.WriteLine("\t[Friendly Name]\n\t\t" + extension.Oid.FriendlyName);
                    Console.WriteLine();

                    Console.WriteLine("\t[OID]\n\t\t" + extension.Oid.Value);
                    Console.WriteLine();

                    Console.WriteLine("\t[Subject Alt Name]\n\t\t" + extension.Format(true));
                    Console.WriteLine();
                }
                else if (extension.Oid.FriendlyName == "Certificate Template Information")
                {
                    Console.WriteLine("\t[Friendly Name]\n\t\t" + extension.Oid.FriendlyName);
                    Console.WriteLine();

                    Console.WriteLine("\t[OID]\n\t\t" + extension.Oid.Value);
                    Console.WriteLine();

                    Console.WriteLine("\t[Certificate Template Information]\n\t\t" + extension.Format(true));
                    Console.WriteLine();
                }
                else
                {
                    Console.WriteLine("\t[Friendly Name]\n\t\t" + extension.Oid.FriendlyName);
                    Console.WriteLine();

                    Console.WriteLine("\t[OID]\n\t\t" + extension.Oid.Value);
                    Console.WriteLine();
                }

                Console.WriteLine("\t\t----------------------------------");
            }
        }
        Console.WriteLine();
    }

    public static bool Export(string thumbprint, X509ContentType type)
    {
        foreach (StoreLocation storeLocation in (StoreLocation[])
            Enum.GetValues(typeof(StoreLocation)))
        {
            foreach (StoreName storeName in (StoreName[])
                Enum.GetValues(typeof(StoreName)))
            {
                X509Store store = new X509Store(storeName, storeLocation);

                try
                {
                    store.Open(OpenFlags.OpenExistingOnly);

                    foreach (X509Certificate2 certificate in (store.Certificates))
                    {
                        if (certificate.GetCertHashString() == thumbprint)
                        {

                            string output = "";

                            if (type == X509ContentType.SerializedCert)
                                output = Convert.ToBase64String(certificate.Export(X509ContentType.SerializedCert));
                            else if (type == X509ContentType.Pfx)
                                output = Convert.ToBase64String(certificate.Export(X509ContentType.Pfx));

                            Console.WriteLine();
                            Console.WriteLine("Output Type: " + type);
                            Console.WriteLine(output);

                            return true;
                        }

                    }
                }
                catch (CryptographicException ex)
                {
                    Console.WriteLine("Failed to export           {0}, {1} for cryptographic error.",
                        store.Name, store.Location);

                    Console.WriteLine("Error message: ");
                    Console.WriteLine(ex.Message);

                    //return false; --> We should continue to search for other stores
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Failed to export           {0}, {1} due to unknown error.",
                        store.Name, store.Location);

                    Console.WriteLine("Error message: ");
                    Console.WriteLine(ex.Message);

                    //return false; --> We should continue to search for other stores
                }
            }

            
        }
        return false;
    }

    
    public static bool Import(string cert, string storename, StoreLocation location, bool verbose = false)
    {
        X509Store store = new X509Store();

        try
        {
            X509Certificate2 certificate = new X509Certificate2();
            certificate.Import(Convert.FromBase64String(cert));

            Console.WriteLine("Certificate read successfully.");

            if (verbose)
                Console.WriteLine("Details: " + certificate.ToString());

            store  = new X509Store(storename, location);
            store.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
            Console.WriteLine("Opened store: {0}", store.Name);

            store.Add(certificate);
            Console.WriteLine("Added certificate to store successfully!");
            store.Close();
            return true;
        }
        catch (CryptographicException ex)
        {
            Console.WriteLine("Failed to import           {0}, {1} for cryptographic error.",
                store.Name, store.Location);

            Console.WriteLine("Error message: ");
            Console.WriteLine(ex.Message);

            return false;
        }
        catch (Exception ex)
        {
            Console.WriteLine("Failed to import           {0}, {1} due to unknown error.",
                store.Name, store.Location);

            Console.WriteLine("Error message: ");
            Console.WriteLine(ex.Message);

            return false;
        }
    }

    public static void Help()
    {
        Console.WriteLine("Examples:\n");

        Console.WriteLine("Display this help message: CertStealer.exe --help");
        Console.WriteLine("Listing all certs: CertStealer.exe --list");
        Console.WriteLine("Listing all certs within the My store in CurrentUser: CertStealer.exe --name user --store My --list");
        Console.WriteLine("Listing all certs within the CA store in LocalMachine: CertStealer.exe --name local --store CA --list");
        Console.WriteLine("Exporting a cert by its thumbprint: CertStealer.exe -export AF724CB571166C24C0799E65BE4772B10814BDD2");
        Console.WriteLine("Exporting a cert by its thumbprint as PFX: CertStealer.exe -export pfx AF724CB571166C24C0799E65BE4772B10814BDD2");
        Console.WriteLine("Importing a cert into the My store in CurrentUser: CertStealer.exe --import My user Dw...snipped...gY=");
        Console.WriteLine("Importing a cert into the CA store in LocalMachine: CertStealer.exe --import CA local Dw...snipped...gY=");
        Console.WriteLine("Use verbose output (works for list and import): CertStealer.exe --list --verbose");
    }
}
