/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package classicapplet1;

import javacard.framework.*;

/**
 *
 * @author Erich
 */
public class ClassicApplet1 extends Applet {
	final byte jmeno[] = {'E', 'R', 'I', 'C', 'H'};
    /**
     * Installs this applet.
     * 
     * @param bArray
     *            the array containing installation parameters
     * @param bOffset
     *            the starting offset in bArray
     * @param bLength
     *            the length in bytes of the parameter data in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new ClassicApplet1(bArray,bOffset,bLength);
    }

    /**
     * Only this class's install method should create the applet object.
     */
    protected ClassicApplet1() {
        register();
    }

    /**
     * Processes an incoming APDU.
     * 
     * @see APDU
     * @param apdu
     *            the incoming APDU
     */
    public void process(APDU apdu) {
        //Insert your code here
         byte buf[]= apdu.getBuffer();
        byte ins = buf[ISO7816.OFFSET_INS];
        byte CLA = buf[ISO7816.OFFSET_CLA];
        
         switch (ins){
            case 0x00:
             
                short le = apdu.setOutgoing();
                apdu.setOutgoingLength((short)jmeno.length);
                apdu.sendBytesLong(jmeno, (short)0 ,(short)jmeno.length);
                break;
            default:
                  ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
         }
    }
}
