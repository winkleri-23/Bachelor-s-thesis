using System;
using PCSC;
using PCSC.Iso7816;
using System.Windows.Forms;
using Microsoft.VisualBasic;
using System.Text;
using System.Security.Cryptography;
using System.Linq;
using System.IO;
using globalplatform.net;
using System.Collections.Generic;

static class Constants
{
    public const int SizeOfEncryptedData = 246;
    public const int BuildKeyINS = 0x62;
    public const int ModulusFirstHalfINS = 0x63;
    public const int ModulusSecondHalfINS = 0x64;
    public const int ModulusThirdQuarterINS = 0x65;
    public const int ModulusFourthQuarterINS = 0x66;
    public const int SendExponentINS = 0x61;
    public const int SelectAppletINS = 0xA4;
    public const int SendPinAPDU = 0x20;
    public const int GetKeyAPDU = 0x11;
    public const int ChangePININS = 0x01;
    public const int sendarr = 0x14;
    public const int InvalidateKeyINS = 0x13;


    public const int SizeOfAPDUData = 128;
    public const int SizeOfRSAKey = 2048;
    public const int PinLen = 4;
}

namespace JavaCardPlugin
{
    /// <summary>
    /// This class provides secure communication with Java card.
    /// </summary>
    public class JavaCard
    {
        /// <summary>
        /// Indicates if the reader is connected to the PC
        /// </summary>
        public bool reader;
        /// <summary>
        /// Card context
        /// </summary>
        SCardContext context1;
        /// <summary>
        /// Name of the currently using card reader
        /// </summary>
        string readerName;
        /// <summary>
        /// Key set of session keys - used for establishing the secure channel
        /// </summary>
        private KeySet scKeys;
        /// <summary>
        /// RSA cipher 
        /// </summary>
        private static RSACryptoServiceProvider csp = new RSACryptoServiceProvider(Constants.SizeOfRSAKey);
        /// <summary>
        /// RSA private key 
        /// </summary>
        private RSAParameters _privateKey;
        /// <summary>
        /// RSA Public key 
        /// </summary>
        private RSAParameters _publicKey;
        /// <summary>
        /// Global platform implementation - provides communication via Secure channel
        /// </summary>
        private GlobalPlatform gp;


        /// <summary>
        /// Let the user choose which one of available card readers will be used 
        /// </summary>
        /// <param name="readerNames">Array of available readers</param>
        /// <returns>Name of the chosen card reader</returns>
        private static string ChooseReader(string[] readerNames)
        {
            
            
            // Show available readers.
            string message1 = "";
            string message2 = "";
            string title1 = "Available readers";

            
            //Console.WriteLine("Available readers: ");
            for (var i = 0; i < readerNames.Length; i++)
            {
                message2 = "[" + i + "] " + readerNames[i] + "\n";
                message1 += message2;
            }

            MessageBox.Show(message1, title1);

            var line = Interaction.InputBox("Enter the number of the reader", "Choose reader", "0", 800, 450);
            
            if(line.Length != 1)
            {
                return null;
            }

            int choice;

            if (int.TryParse(line, out choice) && (choice >= 0) && (choice <= readerNames.Length))
            {
                return readerNames[choice];
            }

            return null;
        }


        /// <summary>
        /// Check the APDU response code
        /// </summary>
        /// <param name="response">APDU response</param>
        /// <returns>if correct - return true, else return false</returns>
        private bool CheckResponse(Response response)
        {
            if (response.SW1 == 0x90 && response.SW2 == 0x00)
            {
                return true;
            }
            else
            {
              
                return false;

            }
        }


        /// <summary>
        /// This function gets pin from the user and send it to Java Card.
        /// </summary>
        /// <returns>If the pin unlocks the card - returns true </returns>
        public bool UnlockCard()
        {
            {

                using (var isoReader = new IsoReader(context1, readerName, SCardShareMode.Shared, SCardProtocol.Any, false))
                {
                    string line = Interaction.InputBox("Enter the pin:", "Pin required", "", 800, 450);
                    if (line.Length != Constants.PinLen)
                    {
                        return false;
                    }
                    //byte[] bytes = new byte[4];
                    byte[] bytes = Encoding.ASCII.GetBytes(line);


                    var apdu = new CommandApdu(IsoCase.Case3Short, isoReader.ActiveProtocol)
                    {
                        CLA = 0x00,
                        INS = Constants.SendPinAPDU,
                        P1 = 0x00,  // Parameter 1
                        P2 = 0x00,  // Parameter 2
                        Data = bytes,

                    };
                    WrapCommand(isoReader, ref apdu);
                    var response = isoReader.Transmit(apdu);
                    ResponseAPDU respo = new ResponseAPDU(response.SW1, response.SW2, response.GetData());
                    ResponseAPDU resp = gp.SecureChannel.unwrap(respo);
                    //MessageBox.Show( response.SW1 + "  " + resp.SW2.ToString());
                    return (CheckResponse(response));

                    }
                
                
            }

           

     
        }

        /// <summary>
        /// Function establishes secure channel between the card and plugin
        /// </summary>
        /// <returns>Return true if the channel is established sucessfully </returns>
        public bool EstablishSecureChannel()
        {
            using (var isoReader = new IsoReader(context1, readerName, SCardShareMode.Shared, SCardProtocol.Any, false))
            {

                byte[] s_additionalEntropy = { 9, 8, 7, 6, 5 };

                // GlobalPlatform variable 
                gp = new GlobalPlatform();

                scKeys = new KeySet();



                FileStream ReadKeys = File.OpenRead(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) + @"\CardKeyEncryted.txt");

                byte[] Key1 = new byte[Constants.SizeOfEncryptedData];
                byte[] Key2 = new byte[Constants.SizeOfEncryptedData];
                byte[] Key3 = new byte[Constants.SizeOfEncryptedData];

                ReadKeys.Read(Key1, 0, Constants.SizeOfEncryptedData);
                ReadKeys.Read(Key2, 0, Constants.SizeOfEncryptedData);
                ReadKeys.Read(Key3, 0, Constants.SizeOfEncryptedData);
                ReadKeys.Close();
                // delete the file so nobody can read it 
                //File.Delete(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) + @"\Cardkey.txt"); // Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) 
                try
                {
                    // set the keys needed for creating the session key
                    scKeys.MacKey = new Key(ProtectedData.Unprotect(Key1, s_additionalEntropy, DataProtectionScope.CurrentUser));
                    scKeys.EncKey = new Key(ProtectedData.Unprotect(Key2, s_additionalEntropy, DataProtectionScope.CurrentUser));
                    scKeys.KekKey = new Key(ProtectedData.Unprotect(Key3, s_additionalEntropy, DataProtectionScope.CurrentUser));
                    //scKeys.MacKey = new Key(MacKeydata);
                    //scKeys.EncKey = new Key(EncKeydata);
                    //scKeys.KekKey = new Key(KekKeydata);

                }
                catch
                {
                    MessageBox.Show("Common Secret is incorrect", "SCP could not be established");
                    return false;
                }

                //FileStream a = File.Create(@"C:\Users\Erich\Documents\Cardkey.txt");
                //a.Write(ProtectedData.Protect(ProtectedData.Unprotect(data, s_additionalEntropy, DataProtectionScope.LocalMachine), s_additionalEntropy, DataProtectionScope.CurrentUser), 0, ProtectedData.Protect(ProtectedData.Unprotect(data, s_additionalEntropy, DataProtectionScope.LocalMachine), s_additionalEntropy, DataProtectionScope.CurrentUser).Length);
                CommandAPDU initUpdate = gp.CreateInitUpdateCommand(scKeys,
                SecurityLevel.C_DECRYPTION| SecurityLevel.C_MAC , GlobalPlatform.SCP_02, GlobalPlatform.IMPL_OPTION_I_15);
                
                // sending init update apdu 

                var apdu = new CommandApdu(IsoCase.Case4Short, isoReader.ActiveProtocol)
                {
                    CLA = (byte)initUpdate.CLA,
                    INS = (byte)initUpdate.INS,
                    P1 = (byte)initUpdate.P1,
                    P2 = (byte)initUpdate.P2,
                    Data = initUpdate.Data
                };


                var response = isoReader.Transmit(apdu);
            

                if (response.SW1 == 0x6C)
                {
                    apdu = new CommandApdu(IsoCase.Case2Short, isoReader.ActiveProtocol)
                    {
                        CLA = 0x00,
                        Instruction = InstructionCode.GetResponse,
                        P1 = 0x00,
                        P2 = 0x00,
                        Le = response.SW2

                    };

                    response = isoReader.Transmit(apdu);

                }
                
                byte[] responseData = response.GetData();
                ResponseAPDU responseToUnwrap = new ResponseAPDU(response.SW1, response.SW2, responseData);
                // process data from received from the Java Card
                gp.ProcessInitUpdateResponse(responseToUnwrap);
                
                // send external authentication command apdu 
                CommandAPDU extAuth = gp.CreateExternalAuthCommand();

                apdu = new CommandApdu(IsoCase.Case3Short, isoReader.ActiveProtocol)
                {
                    CLA = (byte)extAuth.CLA,
                    INS = (byte)extAuth.INS,
                    P1 = (byte)extAuth.P1,
                    P2 = (byte)extAuth.P2,
                    Data = extAuth.Data
                };
                response = isoReader.Transmit(apdu);
                
                // process apdu response
                gp.ProcessExternalAuthResponse(new ResponseAPDU(response.SW1, response.SW2, response.GetData()));



            }
            return true;
        }


        /// <summary>
        /// Send RSA modulus for building RSA public key in the Java Card itself. 
        /// </summary>
        /// <param name="isoReader">Iso reader</param>
        /// <param name="response">APDU response</param>
        /// <param name="apdu">APDU used to send the RSA key modulus</param>
        /// <returns>Returns true if the modulus was sucessfully received</returns>
        private bool SendModulus(IsoReader isoReader,ref Response response, ref CommandApdu apdu) 
        {
            // public key modulus array      
            byte[] array = _publicKey.Modulus;
            //MessageBox.Show("ModulusSize", array.Length.ToString());
            byte[] FirstQuarter = new byte[64];
            byte[] SecondQuarter = new byte[64];
            byte[] ThirdQuarter = new byte[64];
            byte[] FourthQuarter = new byte[64];
            // copy the first half of the modulus into the array
            for(int i= 0; i < 64; i++)
            {
                FirstQuarter[i] = array[i];
            }
            // copy the second half of the modulus into the array
            for (int i =0; i < 64; i++)
            {
                SecondQuarter[i] = array[i + 64];
            }

            for (int i = 0; i < 64; i++)
            {
                ThirdQuarter[i] = array[i + (64 * 2)];
            }

            for (int i = 0; i < 64; i++)
            {
                FourthQuarter[i] = array[i + (64 * 3)];
            }


            // sending the first half into the card
            apdu = new CommandApdu(IsoCase.Case3Short, isoReader.ActiveProtocol)
            {
                CLA = 0x00, 
                INS = Constants.ModulusFirstHalfINS,
                P1 = 0x00,  // Parameter 1
                P2 = 0x00,  // Parameter 2

                Data = FirstQuarter,
            };
            //MessageBox.Show(BitConverter.ToString(FirstHalf), " Modulus1");
            WrapCommand(isoReader, ref apdu);
            
            //MessageBox.Show(BitConverter.ToString(apdu.Data.Length), " Modulus1 - enc");
            
            response = isoReader.Transmit(apdu);
            //MessageBox.Show(response.SW1 + response.SW2.ToString(), " Modulus1 - enc");
            if (CheckResponse(response) == false)
            {
                return false;
            }

            // sending the second half to the java card
            apdu = new CommandApdu(IsoCase.Case3Short, isoReader.ActiveProtocol)
            {
                CLA = 0x00, 
                INS = Constants.ModulusSecondHalfINS,
                P1 = 0x00,  // Parameter 1
                P2 = 0x00,  // Parameter 2
                Data = SecondQuarter,
            };
            //MessageBox.Show(BitConverter.ToString(SecondHalf), " Modulus2");
            WrapCommand(isoReader, ref apdu);
            response = isoReader.Transmit(apdu);
            //MessageBox.Show(response.SW1 + response.SW2.ToString(), " Modulus2 - enc");
            if (CheckResponse(response) == false)
            {
                return false;
            }

            apdu = new CommandApdu(IsoCase.Case3Short, isoReader.ActiveProtocol)
            {
                CLA = 0x00,
                INS = Constants.ModulusThirdQuarterINS,
                P1 = 0x00,  // Parameter 1
                P2 = 0x00,  // Parameter 2
                Data = ThirdQuarter,
            };
            //MessageBox.Show(BitConverter.ToString(SecondHalf), " Modulus2");
            WrapCommand(isoReader, ref apdu);
            response = isoReader.Transmit(apdu);
            //MessageBox.Show(response.SW1 + response.SW2.ToString(), " Modulus3 - enc");
            if (CheckResponse(response) == false)
            {
                return false;
            }

            apdu = new CommandApdu(IsoCase.Case3Short, isoReader.ActiveProtocol)
            {
                CLA = 0x00,
                INS = Constants.ModulusFourthQuarterINS,
                P1 = 0x00,  // Parameter 1
                P2 = 0x00,  // Parameter 2
                Data = FourthQuarter,
            };
            //MessageBox.Show(BitConverter.ToString(SecondHalf), " Modulus2");
            WrapCommand(isoReader, ref apdu);
            response = isoReader.Transmit(apdu);
            //MessageBox.Show(response.SW1 + response.SW2.ToString(), " Modulus4 - enc");
            return CheckResponse(response);
        }

        /// <summary>
        /// Send RSA key exponent for building RSA public key in the Java Card itself. 
        /// </summary>
        /// <param name="isoReader">Iso reader</param>
        /// <param name="response">APDU response</param>
        /// <param name="apdu">APDU used to send the RSA key modulus</param>
        /// <returns>Returns true if the RSA key exponent was sucessfully received</returns>
        private bool SendExponent(IsoReader isoReader, ref Response response, ref CommandApdu apdu)
        {
            // sending RSA key exponent into the Java card
            apdu = new CommandApdu(IsoCase.Case3Short, isoReader.ActiveProtocol)
            {
                CLA = 0x00, 
                INS = Constants.SendExponentINS,
                P1 = 0x00,  // Parameter 1
                P2 = 0x00,  // Parameter 2
                Data = _publicKey.Exponent,

            };
            //MessageBox.Show(BitConverter.ToString(_publicKey.Exponent), " Exponent");
            WrapCommand(isoReader, ref apdu);
            response = isoReader.Transmit(apdu);
            //MessageBox.Show(response.SW1.ToString() + response.SW2.ToString(), " Exponent response");
            return CheckResponse(response);
        }

        /// <summary>
        /// Send APDU which make the card to build the public key. 
        /// </summary>
        /// <param name="isoReader">Iso reader</param>
        /// <param name="response">APDU response</param>
        /// <param name="apdu">APDU used to send the RSA key modulus</param>
        /// <returns>Returns true if the RSA key is sucessfully built </returns>
        private bool BuildKeyCommand(IsoReader isoReader, ref Response response, ref CommandApdu apdu)
        {
            apdu = new CommandApdu(IsoCase.Case2Short, isoReader.ActiveProtocol)
            {
                CLA = 0x00, 
                INS = Constants.BuildKeyINS,
                P1 = 0x00,  // Parameter 1
                P2 = 0x00,  // Parameter 2
                Le = 0x00   
            };


            response = isoReader.Transmit(apdu);
            return CheckResponse(response); 
        }



        /// <summary>
        /// Receiving Database key from Java Card. The key is recieved by 128 bit blocks. 
        /// </summary>
        /// <param name="isoReader">Iso reader</param>
        /// <param name="response">APDU response</param>
        /// <param name="apdu">APDU used to send the RSA key modulus</param>
        /// <returns>Returns decrepted database key stored in byte array </returns>
        private byte [] ReceiveTheKey(IsoReader isoReader, ref Response response, ref CommandApdu apdu)
        {
            byte[] DecryptedKey = new byte[Constants.SizeOfRSAKey];
            byte[] Key = new byte[] { };
            byte[] PartialKey = new byte[Constants.SizeOfAPDUData];
            byte[] data = new byte[] { };
            byte[] falseKey = new byte[] { 0, 0, 0 };


            for(int i = 0; i < Constants.SizeOfRSAKey; i++)
            {
                DecryptedKey[i] = 0; 
            }
            for (int i = 0; i < Constants.SizeOfRSAKey/ Constants.SizeOfAPDUData; i++)
            {
                apdu = new CommandApdu(IsoCase.Case4Short, isoReader.ActiveProtocol)
                {
                    CLA = 0x00,
                    INS = Constants.GetKeyAPDU,
                    P1 = 0x00,
                    P2 = 0x00,
                    Data = new byte[] { 0x12, 0x12, 0x12, 0x12},

                };
                WrapCommand(isoReader,ref apdu);
                response = isoReader.Transmit(apdu);
                if (!response.HasData)
                {
                    MessageBox.Show("No data came back", "Error:");
                    return falseKey;
                }
                else
                {
                    Key = response.GetData();
                    PartialKey = Decrypt(response.GetData().ToArray());

                    for(int j = 0; j < Constants.SizeOfAPDUData; j++)
                    {
                        DecryptedKey[(i * Constants.SizeOfAPDUData) + j] = PartialKey[j];  
                    }

                }
            }
            return DecryptedKey;
        }

        /// <summary>
        /// Function sends all information needed for building the public RSA key in the Java Card and receive database key afterwards. 
        /// </summary>
        /// <returns>Returns database key stored in byte array</returns>

        public byte [] GetRSAKey()
        {
            using (var isoReader = new IsoReader(context1, readerName, SCardShareMode.Shared, SCardProtocol.Any, false))
            {

                byte[] a = new byte[] { };
                byte[] data = new byte[] { };
                byte[] falseKey = new byte[] { 0, 0, 0 };
                RSACipher();
                Response response = null;
                CommandApdu apdu = null;

                if(SendModulus(isoReader, ref response, ref apdu) == false)
                {
                    MessageBox.Show("Java Card did not accept the modulus", "Error!");
                    return falseKey;
                }


                if(SendExponent(isoReader, ref response, ref apdu) == false)
                {
                    MessageBox.Show("Java Card did not accept the exponent", "Error!");
                    return falseKey;
                }


                if(BuildKeyCommand(isoReader, ref response, ref apdu) == false)
                {
                    MessageBox.Show("The key was not build", "Error!");
                    return falseKey;
                }
                             
                byte[] Key = ReceiveTheKey(isoReader, ref response, ref apdu);
                //MessageBox.Show(BitConverter.ToString(Key), " KEY");
                return Key;

            }

        }


        /// <summary>
        /// Decrypt given array using private key
        /// </summary>
        /// <param name="Data">Array to be decrypted</param>
        /// <returns>Returns decrypted data </returns>
        private byte [] Decrypt (byte[] Data)
        {
            byte[] result;
            csp.ImportParameters(_privateKey);
            result = csp.Decrypt(Data, false);
            return result; 
        }

        /// <summary>
        /// Export RSA parameters
        /// </summary>
        private void RSACipher()
        {
            csp = new RSACryptoServiceProvider(Constants.SizeOfRSAKey);
            _privateKey = csp.ExportParameters(true);
            _publicKey = csp.ExportParameters(true);
        }


        /// <summary>
        /// Select the correct applet on Java Card
        /// </summary>
        /// <returns>Returns true if the applet was selected </returns>
        public bool SelectApplet()
        {
            
            {
                try
                {
                    using (var isoReader = new IsoReader(context1, readerName, SCardShareMode.Shared, SCardProtocol.Any, false))
                    {

                        var apdu = new CommandApdu(IsoCase.Case3Short, isoReader.ActiveProtocol)
                        {
                            CLA = 0x00, 
                            INS = Constants.SelectAppletINS,
                            P1 = 0x04,  // Parameter 1
                            P2 = 0x00,  // Parameter 2
                            Data = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x00 },
                        };
                        var response = isoReader.Transmit(apdu);
                        reader = true;
                        return true;
                      
                    }
                }
                catch
                {
                    MessageBox.Show("No card was detected in the reader", "Error:");
                    return false;
                }
            }
               
                      
        }

        /// <summary>
        /// Wrap APDU - encrypt the data in order the send it using secure channel
        /// </summary>
        /// <param name="isoReader">Iso reader which is currently using by the user</param>
        /// <param name="apdu">Apdu to wrap</param>
        /// <returns>Returns wrapped apdu </returns>
        private void WrapCommand (IsoReader isoReader, ref CommandApdu apdu)
        {
            CommandAPDU toWrap = new CommandAPDU(apdu.ToArray());
            toWrap = gp.SecureChannel.wrap(toWrap);
            apdu = new CommandApdu(IsoCase.Case3Short, isoReader.ActiveProtocol)
            {
                CLA = (byte)toWrap.CLA,
                INS = (byte)toWrap.INS,

                P1 = (byte)toWrap.P1,  // Parameter 1
                P2 = (byte)toWrap.P2,  // Parameter 2
                Data = toWrap.Data,
            };
        }

        /// <summary>
        /// Gives the user an option to change the Java Card pin. 
        /// </summary>
        /// <returns>Returns true if the pin was changed</returns>
        public bool ChangePin()
        {
            using (var isoReader = new IsoReader(context1, readerName, SCardShareMode.Shared, SCardProtocol.Any, false))
            {

                string line = Interaction.InputBox("Enter new pin:", "You are about to change your pin", "", 800, 450);
                if (line.Length != Constants.PinLen)
                {
                    return false;
                }
                //byte[] bytes = new byte[4];
                byte[] bytes = Encoding.ASCII.GetBytes(line);

                var apdu = new CommandApdu(IsoCase.Case3Short, isoReader.ActiveProtocol)
                {
                    CLA = 0x00,
                    INS = Constants.ChangePININS,
                    P1 = 0x00,  // Parameter 1
                    P2 = 0x00,  // Parameter 2
                    Data = bytes,
                };


                WrapCommand(isoReader, ref apdu);

                var response = isoReader.Transmit(apdu);

                for (int i = 0; i < bytes.Length; i++)
                {
                    bytes[i] = 0;
                }
                return CheckResponse(response);
            }

        }

        /// <summary>
        /// Send APDU reset command. - 
        /// </summary>
        /// <returns>Returns true if the database key was sucessfully invalidate</returns>
        public bool InvalidateDatabaseKey()
        {
            using (var isoReader = new IsoReader(context1, readerName, SCardShareMode.Shared, SCardProtocol.Any, false))
            {

                var apdu = new CommandApdu(IsoCase.Case2Short, isoReader.ActiveProtocol)
                {
                    CLA = 0x00,
                    INS = Constants.InvalidateKeyINS,
                    P1 = 0x00,  // Parameter 1
                    P2 = 0x00,  // Parameter 2
                    Le= 0x00,
                };


                WrapCommand(isoReader, ref apdu);

                var response = isoReader.Transmit(apdu);
                return CheckResponse(response);
            }

        }

        /// <summary>
        /// Constructor of the class - creating Scard context
        /// </summary>
        public JavaCard()
        {
            reader = false;
            // Establish Smartcard context
            //using (var context = new SCardContext())

                context1 = new SCardContext();
                context1.Establish(SCardScope.System);
                
                
                var readerNames = context1.GetReaders();
                if (readerNames == null || readerNames.Length < 1)
                {
                    //Console.WriteLine("You need at least one reader in order to run this example.");
                    string message1 = "You need at least one reader in order to run this example.";
                    MessageBox.Show(message1, "");
                    //Console.ReadKey();
                    return;
                }

                readerName = ChooseReader(readerNames);
                
                if (readerName == null)
                {
                    return;
                }

        }

        ~JavaCard()
        {
            csp.Clear();
            context1.Dispose();
        }

       
        
    }

    }