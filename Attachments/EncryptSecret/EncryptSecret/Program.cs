using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace EncryptSecret
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] s_additionalEntropy = { 9, 8, 7, 6, 5 };
            byte[] data1 = new byte[16];
            byte[] data2 = new byte[16];
            byte[] data3 = new byte[16];
            
           

            string [] lines = File.ReadAllLines((Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) + @"\NewKeyUnencryted.txt"));
            
            data1 = Encoding.ASCII.GetBytes(lines[0]);
            data2 = Encoding.ASCII.GetBytes(lines[1]);
            data3 = Encoding.ASCII.GetBytes(lines[2]);


            byte[] encryptedData1 = ProtectedData.Protect(data1, s_additionalEntropy, DataProtectionScope.CurrentUser);
            byte[] encryptedData2 = ProtectedData.Protect(data2, s_additionalEntropy, DataProtectionScope.CurrentUser);
            byte[] encryptedData3 = ProtectedData.Protect(data3, s_additionalEntropy, DataProtectionScope.CurrentUser);
            byte[] newline = Encoding.ASCII.GetBytes(Environment.NewLine);
            FileStream WriteKeys = File.OpenWrite(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) + @"\CardKeyEncryted.txt");

            WriteKeys.Write(encryptedData1,0,encryptedData1.Length);
            //WriteKeys.Write(newline, 0, newline.Length);
            WriteKeys.Write(encryptedData2, 0, encryptedData2.Length);
            //WriteKeys.Write(newline, 0, newline.Length);
            WriteKeys.Write(encryptedData3, 0, encryptedData3.Length);

            WriteKeys.Close();

        }
    }
}
