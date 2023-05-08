//MIT License

//Copyright (c) 2023 Vassilis Ioannidis (sqltattoo.com)

//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this software and associated documentation files (the "Software"), to deal
//in the Software without restriction, including without limitation the rights
//to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//copies of the Software, and to permit persons to whom the Software is
//furnished to do so, subject to the following conditions:

//The above copyright notice and this permission notice shall be included in
//all copies or substantial portions of the Software.

//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//THE SOFTWARE.


using Azure;
using Azure.Identity;
using Azure.Storage;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Azure.Storage.Blobs.Specialized;
using Azure.Storage.Sas;
using Microsoft.VisualBasic;
using System.ComponentModel;
using System.Net.NetworkInformation;
using System;
using System.Collections.Generic;
using System.Net;
using System.Xml.Linq;
using Azure.Security.KeyVault.Secrets;
using Azure.Core;
using System.Security.Cryptography;

string connectionString = "";
string accountName = "";
string accountKey = "";
string? kvUri = "";
string? kvComment = "";
string? sasName = "";

string? containerName = "";
string? blobName = "";
string? storedAPName = null;
object permissions = 0;

//variables for the data from the app registration in your AzureAD where you have created the app registration
string? tenantId = "";
string? clientId = "";
string? clientSecret = "";

//set the uri for the key vault that holds your storage account connection string, account name and account key
//and where you will store the SAS tokens generated
kvUri = "";
kvComment = "";

//if command line argument is "init" then set the environment variables for the Azure AD App Registration and the Key Vault uri
if (args.Length == 1 && args[0] == "init")
{
    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine("INIT PROCEDURE STARTING...");
    Console.WriteLine("");
    Console.WriteLine("Please supply the following information for your Azure AD App Registration:");
    Console.Write("Tenant ID: ");
    Console.ForegroundColor = ConsoleColor.White;
    tenantId = Console.ReadLine();
    if (string.IsNullOrEmpty(tenantId))
    {
        Console.ForegroundColor = ConsoleColor.Red;
        //write out an error message and return
        Console.WriteLine("Invalid input. Execution stopped.");
        return;
    }
    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.Write("Client ID: ");
    Console.ForegroundColor = ConsoleColor.White;
    clientId = Console.ReadLine();
    if (string.IsNullOrEmpty(clientId))
    {
        Console.ForegroundColor = ConsoleColor.Red;
        //write out an error message and return
        Console.WriteLine("Invalid input. Execution stopped.");
        return;
    }
    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.Write("Client Secret: ");
    Console.ForegroundColor = ConsoleColor.White;
    clientSecret = Console.ReadLine();
    if (string.IsNullOrEmpty(clientSecret))
    {
        Console.ForegroundColor = ConsoleColor.Red;
        //write out an error message and return
        Console.WriteLine("Invalid input. Execution stopped.");
        return;
    }
    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.Write("Key Vault URI: ");
    Console.ForegroundColor = ConsoleColor.White;
    kvUri = Console.ReadLine();
    if (string.IsNullOrEmpty(kvUri))
    {
        Console.ForegroundColor = ConsoleColor.Red;
        //write out an error message and return
        Console.WriteLine("Invalid input. Execution stopped.");
        return;
    }

    //set the environment variables for the Azure AD App Registration and the Key Vault uri
    Environment.SetEnvironmentVariable("SASKEEP1", EncryptionUtils.ProtectData(tenantId), EnvironmentVariableTarget.User);
    Environment.SetEnvironmentVariable("SASKEEP2", EncryptionUtils.ProtectData(clientId), EnvironmentVariableTarget.User);
    Environment.SetEnvironmentVariable("SASKEEP3", EncryptionUtils.ProtectData(clientSecret), EnvironmentVariableTarget.User);
    Environment.SetEnvironmentVariable("SASKEEP4", EncryptionUtils.ProtectData(kvUri), EnvironmentVariableTarget.User);

    Console.ForegroundColor= ConsoleColor.Cyan;
    Console.WriteLine(" Environment variables set successfully.");
    Console.ForegroundColor = ConsoleColor.White;
    Console.Clear();
    Console.WriteLine(" Please restart the tool normally, without the'init' argument.");
    Console.WriteLine(" Close and re-open the command shell to load new environment variables.");
    Console.WriteLine(" Execution stopped.");
    return;
}



//NORMAL PROGRAM FLOW FROM HERE ON
Console.Clear();
Console.WriteLine("Welcome to SASKeep!");
Console.WriteLine("This tool will help you generate SAS tokens for your Azure Storage Account Containers and/or their blobs");
Console.WriteLine("It is intended to be used from an Azure IT/SecOps engineer or related IT professional.");
Console.WriteLine("");

try
{
    //get the environment variables for the Azure AD App Registration and the Key Vault uri
    string? encTenantId = Environment.GetEnvironmentVariable("SASKEEP1");
    tenantId = EncryptionUtils.UnprotectData(encTenantId);

    string? encClientId = Environment.GetEnvironmentVariable("SASKEEP2");
    clientId = EncryptionUtils.UnprotectData(encClientId);

    string? encClientSecret = Environment.GetEnvironmentVariable("SASKEEP3");
    clientSecret = EncryptionUtils.UnprotectData(encClientSecret);

    string? encKvUri = Environment.GetEnvironmentVariable("SASKEEP4");
    kvUri = EncryptionUtils.UnprotectData(encKvUri);

    //if any of the environment variables is null or empty then throw an exception
    if (string.IsNullOrEmpty(tenantId) || string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret) || string.IsNullOrEmpty(kvUri))
    {
        Console.ForegroundColor = ConsoleColor.Red;
        throw new Exception("One or more environment variables are missing. Please run the tool with the \"init\" argument to set them.");
    }   

    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.Write(">>> Please wait while fetching information...");
    var kvClient = new SecretClient(new Uri(kvUri), new ClientSecretCredential(tenantId, clientId, clientSecret));

    connectionString = kvClient.GetSecret("accountConnectionString").Value.Value;
    accountName = kvClient.GetSecret("accountName").Value.Value;
    accountKey = kvClient.GetSecret("accountKey").Value.Value;
    Console.Write(" info fetched successfully!");
    Console.WriteLine("");
}
catch (Exception ex)
{
    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine("Error: " + ex.Message);
    return;
}

Console.ForegroundColor = ConsoleColor.Cyan;
Console.WriteLine(" *** FYI using key vault: " + kvUri + " ***");
Console.WriteLine("");
Console.ForegroundColor = ConsoleColor.Cyan;
Console.WriteLine("Please choose: ");
Console.WriteLine("-------------------------");
Console.WriteLine(" 1. Ad-hoc permissions");
Console.WriteLine(" 2. Stored Access Policy");
Console.WriteLine(" 3. Exit");
Console.WriteLine("-------------------------");
Console.Write("");
Console.Write("Input 1, 2, or 3: ");

Console.ForegroundColor = ConsoleColor.White;
var choice = Console.ReadLine();
if (string.IsNullOrEmpty(choice))
{
    Console.Clear();
    Console.ForegroundColor = ConsoleColor.White;
    //write out an error message and return
    Console.WriteLine("Invalid input. Execution stopped.");
    return;
}
else if (choice == "3")
{
    Console.Clear(); 
    Console.ForegroundColor = ConsoleColor.White;
    return;
}
else if (choice == "1")
{
    permissions = ParsePermissions(1);
}
else if (choice == "2")
{
    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.Write(" Supply existing stored Access Policy name or type in 'new' to create a new one: ");
    Console.ForegroundColor = ConsoleColor.White;
    storedAPName = Console.ReadLine();
    if (!string.IsNullOrEmpty(storedAPName))
    {
        if (storedAPName == "new")
        {
            //get the user input for new stored access policy
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.Write(" Please supply a name for the new access policy: ");
            Console.ForegroundColor = ConsoleColor.White;
            storedAPName = "&" + Console.ReadLine();
            //check storedAPName for invalid user input and set it to null if it is invalid
            if (string.IsNullOrEmpty(storedAPName))
            {
                //write out an error message and return
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("  Invalid input. Execution stopped.");
                return;
            }
            else
            {
                permissions = ParsePermissions(2);
            }
        }
    }
}

Console.ForegroundColor = ConsoleColor.Cyan;
Console.Write("B. Azure Storage Account container name? ");
Console.ForegroundColor = ConsoleColor.White;
containerName = Console.ReadLine();
if (string.IsNullOrEmpty(containerName))
{
    Console.ForegroundColor = ConsoleColor.Red;
    //write out an error message and return
    Console.WriteLine(" Invalid input. Execution stopped.");
    return;
}
Console.ForegroundColor = ConsoleColor.Cyan;
Console.Write("C. SAS on Container or Blob level? (options: c or b respectively): ");
Console.ForegroundColor = ConsoleColor.White;
var type = Console.ReadLine();
if (type == "b")
{
    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.Write(" Blob file name, i.e. file1.png: ");
    Console.ForegroundColor = ConsoleColor.White;
    blobName = Console.ReadLine();
    if (string.IsNullOrEmpty(blobName))
    {
        Console.ForegroundColor = ConsoleColor.Red;
        //write out an error message and return
        Console.WriteLine(" Invalid input. Execution stopped.");
        return;
    }
}
else if (type == "c")
{
    blobName = "";
}
else
{
    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine(" Invalid choice. Execution stopped.");
    return;
}

Console.ForegroundColor = ConsoleColor.Cyan;
// Get the user input for the start and end times for the SAS check for empty or null or invalid start and expiry times
Console.Write("D. Start time? (format: yyyy-MM-ddTHH:mm:ssZ) [hit 'Enter' to default to 1 hour ago]: ");
Console.ForegroundColor = ConsoleColor.White;
var start = Console.ReadLine();
//in case the user does not supply a start time then set it to 1 hour ago
if (string.IsNullOrEmpty(start))
{
    start = DateTimeOffset.UtcNow.AddHours(-1).ToString();
}
Console.ForegroundColor = ConsoleColor.Cyan;
Console.Write("E. Expiry time? (format: yyyy-MM-ddTHH:mm:ssZ) [hit 'Enter' to default to 1 hour from now]: ");
Console.ForegroundColor = ConsoleColor.White;
var expiry = Console.ReadLine();
//in case the user does not supply an expiry time then set it to 1 hour from now
if (string.IsNullOrEmpty(expiry))
{
    expiry = DateTimeOffset.UtcNow.AddHours(1).ToString();
}
//convert the start and expiry times to DateTimeOffset
DateTimeOffset startTime = DateTimeOffset.Parse(start);
DateTimeOffset expiryTime = DateTimeOffset.Parse(expiry);

Console.ForegroundColor = ConsoleColor.Cyan;
Console.Write("F. Name of the SAS to store in key vault? ");
Console.ForegroundColor = ConsoleColor.White;
sasName = Console.ReadLine();
if (string.IsNullOrEmpty(containerName))
{
    Console.ForegroundColor = ConsoleColor.Red;
    //write out an error message and return
    Console.WriteLine(" Invalid input. Execution stopped.");
    return;
}

//get optionally a comment for the SAS in the key vault secret
Console.ForegroundColor = ConsoleColor.Cyan;
Console.Write("G. Any comment for the SAS in the key vault? (optional) ");
Console.ForegroundColor = ConsoleColor.White;
kvComment = Console.ReadLine();
if (string.IsNullOrEmpty(kvComment))
{
    kvComment="";
}

// Generate SAS token for blob or container
GetBlobUri(accountName, accountKey, connectionString, containerName, startTime, expiryTime, blobName, permissions,
        tenantId, clientId, clientSecret, kvUri, sasName, kvComment, storedAPName);

static object ParsePermissions(int permType)
{
    BlobAccountSasPermissions permissions = 0;

    //the perms variable is a string that contains the permissions you want to set
    //the permissions are set as a string of characters that represent the permissions
    //the characters are as follows: r = read, w = write, d = delete, l = list
    //the permissions are set in the order of read, write, delete, list
    //if perms is empty then make it "r"
    Console.WriteLine("");
    Console.ForegroundColor= ConsoleColor.Cyan;
    Console.WriteLine("___________________________________________________________________");
    Console.WriteLine("A. Permissions? (can be a combination of: r,w,d,l or type-in 'all') ");
    Console.WriteLine("   example 1: rwdl");
    Console.WriteLine("   example 2: rl");
    Console.WriteLine("   example 3: all");
    Console.Write("Permissions to set? ");
    Console.ForegroundColor = ConsoleColor.White;
    var perms = Console.ReadLine();


    if (perms == "all")
    {
        perms = "rdwl";
    }
    else if (string.IsNullOrEmpty(perms))
    {
        perms = "r";
        Console.ForegroundColor = ConsoleColor.Magenta;
        Console.WriteLine(" ...Persmissions set as 'read'");
    }

    foreach (char c in perms.ToLower())
    {
        switch (c)
        {
            case 'r':
                permissions |= BlobAccountSasPermissions.Read;
                break;
            case 'w':
                permissions |= BlobAccountSasPermissions.Write;
                break;
            case 'd':
                permissions |= BlobAccountSasPermissions.Delete;
                break;
            case 'l':
                permissions |= BlobAccountSasPermissions.List;
                break;
            case 'a':
                permissions |= BlobAccountSasPermissions.Add;
                break;
            case 'c':
                permissions |= BlobAccountSasPermissions.Create;
                break;
            default:
                Console.ForegroundColor = ConsoleColor.Red;
                throw new ArgumentException($"Invalid permission '{c}'");
        }
    }

    if (permType == 1)
    {
        return permissions;
    }
    else
    {
        return perms;
    }

}

static void GetBlobUri(string accountName, string accountKey, string connectionString, string containerName,
            DateTimeOffset startTime, DateTimeOffset expiryTime, string blobName, object perms,
            string tenantID, string AppID, string clientSecret, string kvUri, string? sasName, string? kvComment, 
            string? storedPolicyName = null)
{
    Uri blobUri = new Uri("https://" + accountName + ".blob.core.windows.net/" + containerName + (string.IsNullOrEmpty(blobName) ? "" : "/" + blobName));
    BlobServiceClient client = new BlobServiceClient(blobUri, new DefaultAzureCredential());

    //var client = new BlobServiceClient(connectionString);
    var container = client.GetBlobContainerClient(containerName);
    var blobClient = container.GetBlobClient(blobName);

    string? spname = storedPolicyName; //local variable to hold the stored access policy name for further manipulation if new policy is created

    BlobSasBuilder sasBuilder = new BlobSasBuilder();

    sasBuilder.BlobContainerName = containerName;
    sasBuilder.Protocol = SasProtocol.Https;

    // Create a UserDelegationKey object to hold the user delegation key
    //UserDelegationKey userDelegationKey = client.GetUserDelegationKey(startTime, expiryTime);

    if (blobName != "")
    {
        sasBuilder.BlobName = blobName;
        sasBuilder.Resource = "b";
    }
    else
    {
        sasBuilder.Resource = "c";
    };

    if (storedPolicyName == null) //go with ad-hoc rights
    {
        sasBuilder.StartsOn = startTime;
        sasBuilder.ExpiresOn = expiryTime;

        // assume that perms object contains the string representation of a BlobAccountSasPermissions value
        if (Enum.TryParse(perms.ToString(), out BlobAccountSasPermissions permissions))
        {
            // the conversion was successful
            // you can now use the "permissions" variable to access the BlobAccountSasPermissions value
            sasBuilder.SetPermissions(permissions);
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Red;
            // the conversion failed
            // handle the error here
            Console.WriteLine("  Error while converting object perms to blob account SAS permissions. Execution stopped.");
        }
    }
    else //go with the stored access policy rights
    {
        if (storedPolicyName.StartsWith("&")) //"&" means that this is a new access policy
        {

            spname = storedPolicyName.Substring(1, storedPolicyName.Length - 1);

            BlobContainerClient containerClient = new BlobContainerClient(connectionString, containerName);

            try
            {
                //await containerClient.CreateIfNotExistsAsync();

                //Get the current access policy for the container, if one exists
                BlobContainerAccessPolicy? currentAP = null;
                try
                {
                    currentAP = containerClient.GetAccessPolicy();
                    //check the number of policies in the container
                    if (currentAP.SignedIdentifiers.Count() > 4)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("  The maximum number of stored access policies for a container is 5. Execution stopped.");
                        return;
                    }
                }
                catch
                {
                    // No access policy exists for the container, create a new BlobContainerAccessPolicy instance with no policies
                    currentAP = new BlobContainerAccessPolicy();
                }

                // Create one or more stored access policies.
                List<BlobSignedIdentifier> signedIdentifiers = new List<BlobSignedIdentifier>
        {
            new BlobSignedIdentifier
            {
                Id = spname,
                AccessPolicy = new BlobAccessPolicy
                {
                    StartsOn = startTime,
                    ExpiresOn = expiryTime,
                    Permissions = perms.ToString()
                }
            }
        };
                // Set the container's access policy.
                if (currentAP.SignedIdentifiers != null)
                {
                    signedIdentifiers.AddRange(currentAP.SignedIdentifiers);
                }
                containerClient.SetAccessPolicy(permissions: signedIdentifiers);                
                
            }
            catch (RequestFailedException e)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("  " + e.ErrorCode);
                Console.WriteLine("  " + e.Message);
            }
        }

        sasBuilder.Identifier = spname;
    }

    // Generate the SAS token
    string sasToken = sasBuilder.ToSasQueryParameters(new StorageSharedKeyCredential(accountName, accountKey)).ToString();
    //string sasToken = sasBuilder.ToSasQueryParameters(userDelegationKey, client.AccountName).ToString();

    // Use the SAS token in your API call
    string urlWithSasToken = $"{client.Uri}?" + sasToken;
 
    try
    {
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.Write("  >>Saving token to designated key vault...");
        var credential = new ClientSecretCredential(tenantID, AppID, clientSecret);
        //save the SAS URI to a an azure key vault secret
        var kvClient = new SecretClient(new Uri(kvUri), credential);
        //add content type to the secret
        var kvSecret = new KeyVaultSecret(sasName, urlWithSasToken);
        kvSecret.Properties.ContentType = kvComment;
        //add secret to key vault
        kvClient.SetSecret(kvSecret);
        Console.Write(" Saved!");
        Console.WriteLine("");
    }
    catch(Exception e)
    {
        Console.ForegroundColor= ConsoleColor.Red;
        Console.WriteLine(e.Message);
    }

    Console.ForegroundColor = ConsoleColor.Green;
    Console.WriteLine("");
    Console.WriteLine("!!!!!! Here is your SAS Uri and token for requested object: {0}", urlWithSasToken);
    Console.WriteLine("");
    Console.ForegroundColor = ConsoleColor.White;
    Console.WriteLine("Hit any key to clear and exit...");
    Console.Read();
    Console.Clear();
    Console.WriteLine("Thank you. Bye!");
}

