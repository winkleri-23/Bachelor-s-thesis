package FinalTest;

import javacard.framework.*;
import org.globalplatform.SecureChannel;
import org.globalplatform.GPSystem;
import javacard.framework.JCSystem;
import javacard.security.RandomData;
import javacard.framework.Util;
import javacard.security.*;
import javacardx.crypto.Cipher;


public class FinalTest extends Applet
{


    byte[] TransientArray =null;
    OwnerPIN pin = new OwnerPIN((byte) 10, (byte) 4);
    /*Default pin*/
    final byte PIN [] = {'1','2','3','4'};
    /*User pin*/
	byte [] USERPIN = new byte [4];
  
  final static byte INIT_UPDATE       = (byte) 0x50;

  final static byte EXT_AUTHENTICATE  = (byte) 0x82;

  final static byte STORE_DATA        = (byte) 0xE2;
  
  final static byte SEND_KEY		  = (byte) 0x11;
  
  final static byte PIN_CHECK		  = (byte) 0x20;
  
  final static byte SEND_ENCRYPTED_KEY		  = (byte) 0x99;
  
  final static byte RECEIVE_MODULUS_FIRST	 = (byte)0x63;
  
  final static byte RECEIVE_MODULUS_SECOND   = (byte) 0x64;
  
  final static byte RECEIVE_MODULUS_THIRD	 = (byte) 0x65;
  
  final static byte RECEIVE_MODULUS_FOURTH   = (byte) 0x66;
  
  final static byte CHANGE_PIN				 = (byte) 0x01;
  
  final static byte RECEIVE_EXPONENT   = (byte) 0x61;
  
  final static byte BUILD_PUBLIC_KEY   = (byte) 0x62;
  
  final static byte RESET				= (byte) 0x13;
  
  final static short SizeOfRSAKey		=  (short) 2048;
  
  final static short SizeofDatabaseKey  = (short) 2048;
  
  final static short SizeOfAPDU			= (short) 128;
	
  final static short IncorrectPIN		= (short) 0x6301;
  
           
   
    
	/*RSA - Modulus - received from the KeePass plugin*/
	byte [] RSA_KEY_MODULUS_NEW = new byte [256];
	/*RSA - Exponent - received from the KeePass plugin*/
	byte [] RSA_PUBLIC_KEY_EXPONENT_NEW = new byte[3];
	
	// serve for sending encrypted data
    byte [] outbuffer = new byte[256];
    
    /*The key from the KeePass Database*/
    byte [] BigDatabaseKey = new byte[SizeofDatabaseKey];
    
    
    /*RSA Cipher*/ 
    Cipher cipherENC = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
	Cipher cipherDEC = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
	/*RSA Public Key */
	RSAPublicKey rsaPublicKey = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_2048, false);
	
	// determine if the KeePass database has been created - if the new Database key should be created or not
	boolean initialized = false; 
	//Key a  = KeyBuilder.buildKey(KeyBuilder.TYPE_AES, (short) 2048, true);
	short counter;


	public static void install(byte[] bArray, short bOffset, byte bLength) 
	{
		new FinalTest(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}
	

	
  protected FinalTest(byte[] bArray,short bOffset,byte bLength){


  
  /*pin*/
  byte iLen = bArray[bOffset]; 
  bOffset = (short) (bOffset + iLen + 1);
  byte cLen = bArray[bOffset]; 
  bOffset = (short) (bOffset + cLen + 1);
  byte aLen = bArray[bOffset]; 
  pin.update(PIN, (short)0,(byte) 0x04 );

  counter= 0;
  /*pin*/
  register();
  }
  
  public boolean select() {

// The applet declines to be selected
// if the pin is blocked.
  if ( pin.getTriesRemaining() == 0 )
  return false;

  return true;

}

public void deselect() {

  // reset the pin value
  pin.reset();

}




	public void process(APDU apdu)
	{
		if (selectingApplet())
		{
            ISOException.throwIt(ISO7816.SW_NO_ERROR);
			return;
		}
		
		// Secure Channel 
		SecureChannel sc = GPSystem.getSecureChannel();
	
		short inlength;
		short respLen;
		
		byte[] buf = apdu.getBuffer();
		switch (buf[ISO7816.OFFSET_INS])
		{
			case INIT_UPDATE:

            case EXT_AUTHENTICATE:
				//sc = GPSystem.getSecureChannel();
                inlength = apdu.setIncomingAndReceive();
                // process the data from plugin - creating a session key
                respLen = sc.processSecurity(apdu);
                apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, respLen);
                
            break;

            case STORE_DATA:
                //Receive command data
                inlength = apdu.setIncomingAndReceive();
                inlength = sc.unwrap(buf, (short) 0, inlength);
                apdu.setOutgoingAndSend((short)0, inlength);
            break;
        case (byte) SEND_KEY:
        	
        	if(!pin.isValidated()){
                ISOException.throwIt(IncorrectPIN);
                break;
            }
			if(initialized == false){
	        	//generate the database key - if new database is being created 
	        	RandomData random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
	        	// SecureRandom does not support generating 2048 bits at once
	        	random.generateData(BigDatabaseKey, (short) 0 , (short) (SizeOfRSAKey/2) );
	        	random.generateData(BigDatabaseKey, (short) (SizeOfRSAKey/2) , (short) (SizeOfRSAKey/2));
	        	initialized = true;
        	}
        	
        	Util.arrayFillNonAtomic(outbuffer,(short)0, (short) outbuffer.length, (byte)0);
        	 
        	short delka = apdu.setIncomingAndReceive();

		
	        /*encryption*/
			cipherENC.init(rsaPublicKey, Cipher.MODE_ENCRYPT);
			short length = cipherENC.doFinal(BigDatabaseKey, (short)(SizeOfAPDU*counter), (short)(SizeOfAPDU), outbuffer, (short)0);
			/*encryption*/
			counter++;
		
			// 2048 bit key - each APDU sends 128 bit of the key - 2048 / 128 = 16 
			if(counter == SizeOfRSAKey/SizeOfAPDU){
				counter = 0;
			}
			short l = apdu.setOutgoing();
			apdu.setOutgoingLength((short)outbuffer.length );
			apdu.sendBytesLong(outbuffer, (short)0 ,(short)outbuffer.length);
        	ISOException.throwIt(ISO7816.SW_NO_ERROR);	
        	break;
        case(byte) RESET:
        	// in case the invalidation of the database key is needed
        	if(!pin.isValidated()){
                ISOException.throwIt(IncorrectPIN);
                break;
            }
        
        	initialized = false;
        	ISOException.throwIt(ISO7816.SW_NO_ERROR);	
        	break;
		case PIN_CHECK:
			// Unlocking the card using a correct pin
            short Lenght = apdu.setIncomingAndReceive();
            // the pin is sent in wrapped APDU - Secure Channel 
            Lenght = sc.unwrap(buf,(short) 0  ,(short) (buf[ISO7816.OFFSET_LC] + 5)  );
            if(buf[ISO7816.OFFSET_LC] != (short) 4){
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            if(pin.check(buf, ISO7816.OFFSET_CDATA, (byte) 4)){
                ISOException.throwIt(ISO7816.SW_NO_ERROR);
            }else{
                 ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
            break;
            
        case RECEIVE_MODULUS_FIRST:
        	if(!pin.isValidated()){
                ISOException.throwIt(IncorrectPIN);
                break;
            }
        	short income = apdu.setIncomingAndReceive();
        	income = sc.unwrap(buf,(short) 0  ,(short) (buf[ISO7816.OFFSET_LC] + 5)  );
        	// receiving first half of RSA modulus from the KeePass plugin
        	Util.arrayCopy(buf,(short)ISO7816.OFFSET_CDATA, RSA_KEY_MODULUS_NEW, (short) 0 , (short) 64);
        	ISOException.throwIt(ISO7816.SW_NO_ERROR);	
        	break;
        case RECEIVE_MODULUS_SECOND:
        	if(!pin.isValidated()){
                ISOException.throwIt(IncorrectPIN);
                break;
            }
        	income = apdu.setIncomingAndReceive();
        	income = sc.unwrap(buf,(short) 0  ,(short) (buf[ISO7816.OFFSET_LC] + 5)  );
        	//receiving second half of RSA modulus from the KeePass plugin
        	Util.arrayCopy(buf,(short)ISO7816.OFFSET_CDATA, RSA_KEY_MODULUS_NEW, (short) 64 , (short) 64);
        	ISOException.throwIt(ISO7816.SW_NO_ERROR);
        	break;
        case RECEIVE_MODULUS_THIRD:
        	if(!pin.isValidated()){
                ISOException.throwIt(IncorrectPIN);
                break;
            }
        	income = apdu.setIncomingAndReceive();
        	income = sc.unwrap(buf,(short) 0  ,(short) (buf[ISO7816.OFFSET_LC] + 5)  );
        	//receiving second half of RSA modulus from the KeePass plugin
        	Util.arrayCopy(buf,(short)ISO7816.OFFSET_CDATA, RSA_KEY_MODULUS_NEW, (short) 128 , (short) 64);
        	ISOException.throwIt(ISO7816.SW_NO_ERROR);
        	break;
        case RECEIVE_MODULUS_FOURTH:
        	if(!pin.isValidated()){
                ISOException.throwIt(IncorrectPIN);
                break;
            }
        	income = apdu.setIncomingAndReceive();
        	income = sc.unwrap(buf,(short) 0  ,(short) (buf[ISO7816.OFFSET_LC] + 5)  );
        	//receiving second half of RSA modulus from the KeePass plugin
        	Util.arrayCopy(buf,(short)ISO7816.OFFSET_CDATA, RSA_KEY_MODULUS_NEW, (short) 192 , (short) 64);
        	ISOException.throwIt(ISO7816.SW_NO_ERROR);
        	break;
        case RECEIVE_EXPONENT:
        	if(!pin.isValidated()){
                ISOException.throwIt(IncorrectPIN);
                break;
            }
        	income = apdu.setIncomingAndReceive();
        	income = sc.unwrap(buf,(short) 0  ,(short) (buf[ISO7816.OFFSET_LC] + 5)  );
        	//receiving a RSA exponent from the KeePass plugin
        	Util.arrayCopy(buf,(short)ISO7816.OFFSET_CDATA, RSA_PUBLIC_KEY_EXPONENT_NEW, (short) 0 , buf[ISO7816.OFFSET_LC]);
        	ISOException.throwIt(ISO7816.SW_NO_ERROR);	
        	break;
        case BUILD_PUBLIC_KEY:
        	// building the public key used for encrypting the Database key
        	if(!pin.isValidated()){
                ISOException.throwIt(IncorrectPIN);
                break;
            }
            // set exponent
        	rsaPublicKey.setExponent(RSA_PUBLIC_KEY_EXPONENT_NEW, (short) 0 ,(short) RSA_PUBLIC_KEY_EXPONENT_NEW.length);
        	// set modulus
			rsaPublicKey.setModulus(RSA_KEY_MODULUS_NEW, (short) 0 , (short)RSA_KEY_MODULUS_NEW.length);
			ISOException.throwIt(ISO7816.SW_NO_ERROR);
			break;
		case CHANGE_PIN:
			if(!pin.isValidated()){
                ISOException.throwIt(IncorrectPIN);
                break;
            }
            income = apdu.setIncomingAndReceive();
            income = sc.unwrap(buf,(short) 0  ,(short) (buf[ISO7816.OFFSET_LC] + 5));
            if(buf[ISO7816.OFFSET_LC] != (short) 4){
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            }
            Util.arrayCopy(buf, (short)ISO7816.OFFSET_CDATA, USERPIN, (short)0 ,buf[ISO7816.OFFSET_LC] );
                        
            pin.update(USERPIN, (short)0,(byte) 0x04 );
            ISOException.throwIt(ISO7816.SW_NO_ERROR);
			break;

		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			
		}
	}

}
