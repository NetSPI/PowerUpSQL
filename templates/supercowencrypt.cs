using System;
using System.Data;
using System.Data.SqlClient;
using System.Data.SqlTypes;
using Microsoft.SqlServer.Server;
using System.Security.Cryptography;
using System.IO;
using System.Diagnostics;
using System.Text;

// Source: https://stackoverflow.com/questions/202011/encrypt-and-decrypt-a-string
// Reference: https://msdn.microsoft.com/en-us/library/system.security.cryptography.aes(v=vs.110).aspx
//
// C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:library c:\temp\commonlib.cs 
//
// CREATE ASSEMBLY commonlib
// FROM 'c:\temp\commonlib.dll'
// WITH PERMISSION_SET = UNSAFE;
// CREATE PROCEDURE [dbo].[beefencrypt] @MyString NVARCHAR (4000) AS EXTERNAL NAME [commonlib].[commonlib].[beefencrypt];
// CREATE PROCEDURE [dbo].[beefdecrypt] @MyString NVARCHAR (4000) AS EXTERNAL NAME [commonlib].[commonlib].[beefdecrypt];
// beefencrypt "hello there"
// beefdecrypt "EAAAAHCGLUEsOXF3Y20X/E8riuIfwqpf/qBfEJuYjttS3VDY"

public partial class commonlib
{
		
	[Microsoft.SqlServer.Server.SqlProcedure]
	public static void beefencrypt (SqlString MyString)
	{           
		try
		{
			string encrypted64 = EncryptStringAES(string.Format(MyString.Value),"aeshidethebeef12345");
	
			// Create the record and specify the metadata for the columns.
			SqlDataRecord record = new SqlDataRecord(new SqlMetaData("output", SqlDbType.NVarChar, 4000));

			// Mark the begining of the result-set.
			SqlContext.Pipe.SendResultsStart(record);

			// Set values for each column in the row
			record.SetString(0, encrypted64);

			// Send the row back to the client.
			SqlContext.Pipe.SendResultsRow(record);

			// Mark the end of the result-set.
			SqlContext.Pipe.SendResultsEnd();
		}
		catch (Exception e)
		{
			Console.WriteLine("Error: {0}", e.Message);
		}					
	}
	
	[Microsoft.SqlServer.Server.SqlProcedure]
	public static void beefdecrypt (SqlString MyString)
	{           
		try
		{
			string decrypted = DecryptStringAES(string.Format(MyString.Value),"aeshidethebeef12345");
	
			// Create the record and specify the metadata for the columns.
			SqlDataRecord record = new SqlDataRecord(new SqlMetaData("output", SqlDbType.NVarChar, 4000));

			// Mark the begining of the result-set.
			SqlContext.Pipe.SendResultsStart(record);

			// Set values for each column in the row
			record.SetString(0, decrypted);

			// Send the row back to the client.
			SqlContext.Pipe.SendResultsRow(record);

			// Mark the end of the result-set.
			SqlContext.Pipe.SendResultsEnd();
		}
		catch (Exception e)
		{
			Console.WriteLine("Error: {0}", e.Message);
		}					
	}	

    private static byte[] _salt = Encoding.Unicode.GetBytes("CaptainSalty");

    public static string EncryptStringAES(string plainText, string sharedSecret)
    {
        if (string.IsNullOrEmpty(plainText))
            throw new ArgumentNullException("plainText");
        if (string.IsNullOrEmpty(sharedSecret))
            throw new ArgumentNullException("sharedSecret");

        string outStr = null;                       // Encrypted string to return
        RijndaelManaged aesAlg = null;              // RijndaelManaged object used to encrypt the data.

        try
        {
            // generate the key from the shared secret and the salt
            Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(sharedSecret, _salt);

            // Create a RijndaelManaged object
            aesAlg = new RijndaelManaged();
            aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);
			aesAlg.Mode = CipherMode.ECB;

            // Create a decryptor to perform the stream transform.
            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            // Create the streams used for encryption.
            using (MemoryStream msEncrypt = new MemoryStream())
            {
                // prepend the IV
                msEncrypt.Write(BitConverter.GetBytes(aesAlg.IV.Length), 0, sizeof(int));
                msEncrypt.Write(aesAlg.IV, 0, aesAlg.IV.Length);
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        //Write all data to the stream.
                        swEncrypt.Write(plainText);
                    }
                }
                outStr = Convert.ToBase64String(msEncrypt.ToArray());
            }
        }
        finally
        {
            // Clear the RijndaelManaged object.
            if (aesAlg != null)
                aesAlg.Clear();
        }

        // Return the encrypted bytes from the memory stream.
        return outStr;
    }

    public static string DecryptStringAES(string cipherText, string sharedSecret)
    {
        if (string.IsNullOrEmpty(cipherText))
            throw new ArgumentNullException("cipherText");
        if (string.IsNullOrEmpty(sharedSecret))
            throw new ArgumentNullException("sharedSecret");

        // Declare the RijndaelManaged object
        // used to decrypt the data.
        RijndaelManaged aesAlg = null;

        // Declare the string used to hold
        // the decrypted text.
        string plaintext = null;

        try
        {
            // generate the key from the shared secret and the salt
            Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(sharedSecret, _salt);

            // Create the streams used for decryption.                
            byte[] bytes = Convert.FromBase64String(cipherText);
            using (MemoryStream msDecrypt = new MemoryStream(bytes))
            {
                // Create a RijndaelManaged object
                // with the specified key and IV.
                aesAlg = new RijndaelManaged();
                aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);
				aesAlg.Mode = CipherMode.ECB;
				
                // Get the initialization vector from the encrypted stream
                aesAlg.IV = ReadByteArray(msDecrypt);
                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))

                        // Read the decrypted bytes from the decrypting stream
                        // and place them in a string.
                        plaintext = srDecrypt.ReadToEnd();
                }
            }
        }
        finally
        {
            // Clear the RijndaelManaged object.
            if (aesAlg != null)
                aesAlg.Clear();
        }

        return plaintext;
    }

    private static byte[] ReadByteArray(Stream s)
    {
        byte[] rawLength = new byte[sizeof(int)];
        if (s.Read(rawLength, 0, rawLength.Length) != rawLength.Length)
        {
            throw new SystemException("Stream did not contain properly formatted byte array");
        }

        byte[] buffer = new byte[BitConverter.ToInt32(rawLength, 0)];
        if (s.Read(buffer, 0, buffer.Length) != buffer.Length)
        {
            throw new SystemException("Did not read byte array properly");
        }

        return buffer;
    }		
}
