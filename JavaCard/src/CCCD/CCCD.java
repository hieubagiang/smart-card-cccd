package CCCD;

import javacard.framework.*;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacardx.apdu.ExtendedLength;
import javacardx.crypto.Cipher;

public class CCCD extends Applet implements ExtendedLength{

    // all data in card
    private byte[] encryptedData;
    private static short dataLength;
    // String data mã hóa.
    final static byte Wallet_CLA = (byte) 0xB0;
    // codes of INS byte in the command APDU header
    private static final byte VERIFY = (byte) 0x20;
    private static final byte REGIST_CARD = (byte) 0x50;
    private static final byte UNBLOCK = (byte) 0x60;
    private static final byte CHANGE_PASS = (byte) 0x70;
    private static final byte GEN_RSA_KEY = (byte) 0xD3;
    private static final byte SIGN_RSA = (byte) 0xD0;
    private static final byte EXPORT_RSA_EXPONENT_KEY = (byte) 0xF2;
    private static final byte EXPORT_RSA_MODULUS_KEY = (byte) 0xF0;
    private static final byte INS_get = (byte) 0x14;
    private static final short MAX_LEN_OUT_GOING = 200;

    
    //mng  send ra apdu các offset logic
    private final static byte[] offSetLogic = {(byte) 0x3A, (byte) 0x00, (byte) 0x01};
    //mng tm, các mng lu gi khóa

    // maximum balance
    final static short MAX_BALANCE = 0x7FFF;

    // maximum transaction amount 
    final static short MAX_TRANSACTION_AMOUNT = 0xFF;

    // maximum number of incorrect tries before the
    // PIN is blocked
    final static byte PIN_TRY_LIMIT = (byte) 0x03;

    // maximum size PIN
    final static byte MAX_PIN_SIZE = (byte) 0x08;

    // signal that the PIN verification failed
    final static short SW_VERIFICATION_FAILED = 0x6312;

    // signal the PIN validation is required
    // for a credit or a debit transaction
    final static short SW_PIN_VERIFICATION_REQUIRED = 0x6311;

    // signal invalid transaction amount
    // amount > MAX_TRANSACTION_MAOUNT or amount < 0
    final static short SW_INVALID_TRANSACTION_AMOUNT = 0x6A83;

    // signal that the balance exceed the maximum
    final static short SW_EXCEED_MAXIMUM_BALANCE = 0x6A84;

    // signal the balance becomes negative
    final static short SW_NEGATIVE_BALANCE = 0x6A85;
    
    private static final byte INS_GET_CARD_DATA = (byte) 0x13;
 
    /* instance variables declaration */
    OwnerPIN initPin;
    AESUltils _aesUtils;
    short balance;
    
    private static byte[] userData;
    
    // RSA
    // use unpadded RSA cipher for signing (so be careful with what you do!)
    Cipher cipherRSA = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
    // an RSA-2048 keypair
    KeyPair rsaPair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_2048);
    RSAPrivateCrtKey rsaKeyPriv;
    RSAPublicKey rsaKeyPub;
    RandomData rng;
    // 256 byte buffer for producing signatures
    byte[] tempBuffer = JCSystem.makeTransientByteArray((short)256, JCSystem.CLEAR_ON_DESELECT);
    // 256 byte buffer to hold the incoming data (which will be hashed)
    byte[] dataBuffer = JCSystem.makeTransientByteArray((short)256, JCSystem.CLEAR_ON_DESELECT);
    // the DER prefix for a SHA256 hash in a PKCS#1 1.5 signature
    private static final byte[] SHA256_PREFIX = {
        (byte) 0x30, (byte) 0x31, (byte) 0x30, (byte) 0x0d,
        (byte) 0x06, (byte) 0x09, (byte) 0x60, (byte) 0x86,
        (byte) 0x48, (byte) 0x01, (byte) 0x65, (byte) 0x03,
        (byte) 0x04, (byte) 0x02, (byte) 0x01, (byte) 0x05,
        (byte) 0x00, (byte) 0x04, (byte) 0x20
    };
    // support for SHA256
    MessageDigest md = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
    
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new CCCD(bArray, (short) (bOffset + 1),bArray[bOffset]);

    }

    /**
     * Only this class's install method should create the applet object.
     */
    protected CCCD(byte[] bArray, short bOffset, byte bLength) {
        // It is good programming practice to allocate
        // all the memory that an applet needs during
        // its lifetime inside the constructor
 
        initPin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
       

        // The installation parameters contain the PIN
        // initializationvalue 
        byte[] pinArr = {1, 2, 3, 4};
        initPin.update(pinArr, (short) 0, (byte) pinArr.length);
        register();
		 _aesUtils = new AESUltils();
        JCSystem.requestObjectDeletion();
    }

    public boolean select() {
        // The applet declines to be selected
        // if the pin is blocked.
        if (initPin.getTriesRemaining() == 0) {
            return false;
        }
        return true;
    }// end of select method

    public void deselect() {
        // reset the pin value
        initPin.reset();
    }

    public void process(APDU apdu) {
        // APDU object carries a byte array (buffer) to
        // transfer incoming and outgoing APDU header
        // and data bytes between card and CAD
        // At this point, only the first header bytes
        // [CLA, INS, P1, P2, P3] are available in
        // the APDU buffer.
        // The interface javacard.framework.ISO7816
        // declares constants to denote the offset of
        // these bytes in the APDU buffer
        byte[] buffer = apdu.getBuffer();
        // check SELECT APDU command
        if ((buffer[ISO7816.OFFSET_CLA] == 0)
                && (buffer[ISO7816.OFFSET_INS] == (byte) (0xA4))) {
            return;
        }

        // verify the reset of commands have the
        // correct CLA byte, which specifies the
        // command structure
        if (buffer[ISO7816.OFFSET_CLA] != Wallet_CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        
        switch (buffer[ISO7816.OFFSET_INS]) {
            case REGIST_CARD:
                initCard(apdu);
                break;
            case INS_GET_CARD_DATA:
                getCardInfo(apdu);
                break;
            case VERIFY:
                verify(apdu);
                return;
            case UNBLOCK:
                initPin.resetAndUnblock();
                return;
            case CHANGE_PASS:
                changePass(apdu);
                return; 
              case (byte)GEN_RSA_KEY:
                // generate a new key
                gen_rsa_key();
                break;
            case (byte)SIGN_RSA:
                // sign a given incoming message
                sign_message(apdu);
                break;
            case (byte)EXPORT_RSA_MODULUS_KEY:
                // retrieve the modulus public key from the card
                getPublicRSA(apdu, (short)0x00);
                break;
            case (byte)EXPORT_RSA_EXPONENT_KEY:
                // retrieve the exponent public key from the card
                getPublicRSA(apdu, (short)0x01);
                break;      
            // case (byte)0x12:
                // apdu.setIncomingAndReceive();
                // Util.arrayCopy(pinArr, (short)0, buffer, (short)0, (short)pinArr.length);
                // apdu.setOutgoingAndSend((short)0, (short)pinArr.length);
                // break;      
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    } // end of process method

	 public void gen_rsa_key(){

        rsaPair.genKeyPair();
        rsaKeyPriv = (RSAPrivateCrtKey) rsaPair.getPrivate();
        rsaKeyPub = (RSAPublicKey) rsaPair.getPublic();
        return;
    }

    private void getPublicRSA(APDU apdu, short choose){

        if (!rsaKeyPub.isInitialized())
        {
                ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        }

        byte[] buffer = apdu.getBuffer();
        short length = 0;

        switch ((short) choose)
        {
        case 0x00:
                length = rsaKeyPub.getModulus(buffer, (short)0);
                break;
        case 0x01:
                length = rsaKeyPub.getExponent(buffer, (short)0);
                break;
        default:

                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        apdu.setOutgoingAndSend((short)0, length);
        return;
    }

    public void sign_message(APDU apdu){
        if (!rsaKeyPriv.isInitialized()){
            // RSA key isn't initialised for some reason... this is not OK
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        // prepare for signing
        // signing being decryption using RSA (be careful here, ensure you understand PKCS#1.5 and don't sign "raw" data!)
        cipherRSA.init(rsaPair.getPrivate(), Cipher.MODE_DECRYPT);
        // get buffer access to APDU
        byte[] buffer = apdu.getBuffer();
        short bytesRead = apdu.setIncomingAndReceive();
        // don't allow excessively long data to be signed, at least for now
        if (bytesRead > 256)
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        // fetch the message to be signed into a temporary buffer
        Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, dataBuffer, (short)0, bytesRead);
        // pkcs1_sha256() will hash the input message of upto 255 bytes, and return a PKCS#1.5 digest to be signed
        pkcs1_sha256(dataBuffer, (short)0, bytesRead);
        // this has sets the tempBuffer as the data to sign

        // sign the contents of temporary buffer, send signature to APDU output buffer
        cipherRSA.doFinal(tempBuffer, (short)0, (short)256, buffer, (short)0);
        // clear the temp buffer
        Util.arrayFillNonAtomic(tempBuffer, (short)0, (short)256, (byte)0x00);
        // clear the data buffer
        Util.arrayFillNonAtomic(dataBuffer, (short)0, (short)256, (byte)0x00);
        // return the signature
        apdu.setOutgoingAndSend((short)0, (short)256);
        return;
    }
    
    // this function will leave tempBuffer with the data to be signed
    public void pkcs1_sha256(byte[] toSign, short bOffset, short bLength){
        // clear the hasher
        md.reset();

        // clear the temp buffer
        Util.arrayFillNonAtomic(tempBuffer, (short)0, (short)256, (byte)0x00);
        // the format of a pkcs1#1.5 digest before signing is as follows:
        // (note that this is pre-computed for a sha256 hash length)

        // 2 bytes, 0x00, 0x01
        // padding (202 bytes of 0xFF)
        // byte 0x00
        // hash-type prefix is 19 bytes
        // hash is 32 bytes

        // therefore the padding contains 256-32-19-3 = 202 bytes
        tempBuffer[0] = (byte) 0x00;
        tempBuffer[1] = (byte) 0x01;
        // add in the padding
        Util.arrayFillNonAtomic(tempBuffer, (short)2, (short)202, (byte)0xFF);
        tempBuffer[204] = (byte) 0x00;
        // copy the DER prefix
        Util.arrayCopyNonAtomic(SHA256_PREFIX, (short)0, tempBuffer, (short)205, (short)SHA256_PREFIX.length);
        // now add the actual hash
        md.doFinal(toSign, bOffset, bLength, tempBuffer, (short)224);
        // the value to sign is in tempBuffer
    }

    
    private void changePass(APDU apdu){        
        if (!initPin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }
        
        byte[] buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();
        short dataLen = (short)(buffer[ISO7816.OFFSET_LC]&0xff);
        
		byte[] pinArr =  new byte[dataLen];

        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, pinArr, (short)0, dataLen);
        
        // Util.arrayCopy(pinArr, (short)0, buffer, (short)0, dataLen);
		// apdu.setOutgoingAndSend((short)0, (short)dataLen);
        initPin.update(pinArr, (short) 0, (byte) pinArr.length);
    }
    
   
    private void verify(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        // retrieve the PIN data for validation.
        byte byteRead = (byte) (apdu.setIncomingAndReceive());

        // check pin
        // the PIN data is read into the APDU buffer
        // at the offset ISO7816.OFFSET_CDATA
        // the PIN data length = byteRead
        if (initPin.check(buffer, ISO7816.OFFSET_CDATA, byteRead) == false) {

            ISOException.throwIt(SW_VERIFICATION_FAILED);
        }
    } // end of validate method

    private void initCard(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        short recvLen = apdu.setIncomingAndReceive(); // mot lan doc
        short dataLen = apdu.getIncomingLength();//(short)(buffer[ISO7816.OFFSET_LC]&0xff); toan bo
        short dataOffset = apdu.getOffsetCdata();

        encryptedData = new byte[dataLen];
        
		
		
        short pointer = 0;	
        while (recvLen > 0) {
            Util.arrayCopy(buffer, apdu.getOffsetCdata(), encryptedData, pointer, recvLen);
            pointer += recvLen;
            recvLen = apdu.receiveBytes(dataOffset);
        }
        encryptedData= _aesUtils.paddingArray(encryptedData, dataLen);
		_aesUtils.doEncryptAesCipher(apdu, encryptedData);
        // Util.arrayCopy(encryptedData, (short)0, buffer, (short)0, (short)encryptedData.length);
		// apdu.setOutgoingAndSend((short)0, (short)encryptedData.length);
		
		
    }
	
    private void getCardInfo(APDU apdu) {
        short toSend = (short) encryptedData.length;

        apdu.setOutgoing();
        apdu.setOutgoingLength(toSend);
        apdu.sendBytesLong(encryptedData, (short)0, toSend);
    }
}
 