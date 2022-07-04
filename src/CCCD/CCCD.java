package CCCD;
import javacard.framework.*;
import javacard.framework.OwnerPIN;
import javacard.security.KeyBuilder;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;
import javacard.security.AESKey;
import javacard.security.Key;
import javacard.security.KeyAgreement;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacardx.apdu.ExtendedLength;
import javacard.security.*;
import javacardx.crypto.*;

public class CCCD extends Applet implements ExtendedLength
{
    private byte[] encryptedData;
	
	final static byte marker =(byte)0x2c;
	
	public static byte isNewUser;

	final static byte APP_CLA =(byte)0x00;
	final static byte INIT_DATA = (byte) 0x01;
	final static byte GET_INFO = (byte) 0x02;
	final static byte IS_INIT_DATA = (byte) 0x03;
	final static byte VERIFY =(byte)0x11;
	final static byte CREATE_PIN =(byte)0x10;
    final static byte UNLOCK_USER = (byte) 0x12;
	final static byte PASSWORD_TRY_LIMIT =(byte)0x03;
	
	
	final static byte GET_EXPORT_PUBLIC_MODUL = (byte)0x20;
	final static byte GET_EXPORT_PUBLIC_EXPONENT = (byte)0x21;
	private static final byte INS_SIGN = (byte)0x22	;

	final static byte MAX_PASS_SIZE =(byte)0x08;
	   // signal that the PIN verification failed
    final static short SW_VERIFICATION_FAILED = 	0x6300;
    final static short SW_CARD_IS_BLOCKED = 0x6302;
    final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;
	/* instance variables declaration */
	static OwnerPIN pin;
	private MessageDigest sha;
	private static Cipher aesCipher;
	private RSAPublicKey rsaPubKey;
	private Signature rsaSig;
	private short sigLen;
	private byte[] s1, s2, s3, sig_buffer;
	private byte[] rsaPrivKeyEncrypted;
	private final static byte[] PIN_INIT_VALUE={(byte)'1',(byte)'2',(byte)'3',(byte)'4'};
	private static short LENGTH_BLOCK_AES = (short)16;
	private static boolean isCreateProfile = false;
	private static AESUltils aesUtils;
	private static short privExponentLength;
	private static short privModulusLength;
	private static short originLength;

	private CCCD(byte[] bArray, short bOffset, byte bLength) {
		  // It is good programming practice to allocate
        // all the memory that an applet needs during
        // its lifetime inside the constructor
        pin = new OwnerPIN(PASSWORD_TRY_LIMIT,(byte)MAX_PASS_SIZE);
        
        byte iLen = bArray[bOffset]; // aid length
        bOffset = (short) (bOffset+iLen+1);
        byte cLen = bArray[bOffset]; // info length
        bOffset = (short) (bOffset+cLen+1);
        byte aLen = bArray[bOffset]; // applet data length
		// init cipher
		byte [] tmpBuffer;
		try {
			tmpBuffer = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);
		} catch (SystemException e) {
			tmpBuffer = new byte[(short) 256];
		}

		sigLen = (short)(KeyBuilder.LENGTH_RSA_1024/8);
		sig_buffer = new byte[sigLen];
		rsaSig = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1,false);
		RSAPrivateKey rsaPrivKey =(RSAPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE,(short)(8*sigLen),false);
		rsaPubKey = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC,(short)(8*sigLen), false);

		KeyPair keyPair = new KeyPair(KeyPair.ALG_RSA,(short)(8*sigLen));
		keyPair.genKeyPair();
		rsaPrivKey = (RSAPrivateKey)keyPair.getPrivate();
			    aesUtils = new AESUltils();

		//encryp privkey
		encryptPrivKey(rsaPrivKey);
		rsaPubKey = (RSAPublicKey)keyPair.getPublic();
		
		sha = MessageDigest.getInstance(MessageDigest.ALG_MD5,false);
        // Sha512.init();
		// HMacSHA512.init(tmpBuffer);
        byte[] keyBytes = JCSystem.makeTransientByteArray(LENGTH_BLOCK_AES, JCSystem.CLEAR_ON_DESELECT);
        try {
        	short shalen = sha.doFinal(PIN_INIT_VALUE, (short)0,(short)PIN_INIT_VALUE.length, keyBytes, (short)0);
            // HMacSHA512.computeHmacSha512(PIN_INIT_VALUE,(short)0x00,(short)PIN_INIT_VALUE.length,keyBytes,(short)0);
            // aesKey.setKey(keyBytes, (short) 0);
            aesUtils.setAesKey(keyBytes);
        } finally {
            Util.arrayFillNonAtomic(keyBytes, (short) 0, LENGTH_BLOCK_AES, (byte) 0);
        }
        // The installation parameters contain the PIN
        // initialization value
		isNewUser= (byte)'1';
		pin.update(PIN_INIT_VALUE, (short) 0, (byte)PIN_INIT_VALUE.length);
        register();
	}
	
	 public boolean select() {
        return true;
    }
    
     public void deselect() {
        // reset the pin value
        pin.reset();
        
    }
	
	public static void install(byte[] bArray, short bOffset, byte bLength) 
	{
		new CCCD(bArray, bOffset, bLength);
	}

	public void process(APDU apdu)
	{
		if (selectingApplet())
		{
			return;
		}

		byte[] buf = apdu.getBuffer();
		short byteRead = (short)(apdu.setIncomingAndReceive());
		short dataLen = (short)(buf[ISO7816.OFFSET_LC]&0xff);
		
		// if ( pin.getTriesRemaining() == 0 ) 
			// ISOException.throwIt(SW_CARD_IS_BLOCKED);
		
		if (buf[ISO7816.OFFSET_CLA] != APP_CLA)
			 ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		
		switch (buf[ISO7816.OFFSET_INS])
		{
		case (byte) CREATE_PIN:
			createPin(apdu,buf);
			break;
		
		case (byte) INIT_DATA:
			initInformation(apdu,buf,byteRead);
			break;
		case (byte) GET_INFO:
			 showInformation(apdu);
			break;
		case (byte) VERIFY:
			verify(apdu,buf,(byte)byteRead);
			break;
		case (byte)UNLOCK_USER: pin.resetAndUnblock();
			return;
		case (byte) INS_SIGN:
			rsaSign(apdu,buf);
			break;
		case (byte) GET_EXPORT_PUBLIC_MODUL:
			exportPublicModulus(apdu);
			break;
		case (byte) GET_EXPORT_PUBLIC_EXPONENT:
			exportPublicExponent(apdu);
			break;
		case (byte) IS_INIT_DATA:
			checkInitData(apdu);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
	
	public void initInformation(APDU apdu,byte[] buf,short recvLen) {
		if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }
		JCSystem.beginTransaction();
		short pointer = 0;
		short dataOffset = apdu.getOffsetCdata();
		short datalength = apdu.getIncomingLength();
		encryptedData=new byte[datalength];
        short dataOffsetInput = 0;
		while (recvLen > 0)
		{
			Util.arrayCopy(buf, dataOffset, encryptedData, pointer,recvLen);
			pointer += recvLen;
			recvLen = apdu.receiveBytes(dataOffset);
		}
		//
		short lenExponent  = rsaPubKey.getModulus(buf, (short) 0);
		isCreateProfile=true;
		apdu.setOutgoingAndSend((short)0, lenExponent);
		originLength= datalength;
        encryptedData= aesUtils.paddingArray(encryptedData, datalength);
		byte[] temp = new byte[encryptedData.length];
		aesUtils.doEncryptAesCipher(encryptedData,temp);
		Util.arrayCopy(temp,(short)0,encryptedData,(short)0,(short)temp.length);
		JCSystem.commitTransaction();	
	}

	private void checkInitData(APDU apdu) {
		byte buffer[] = apdu.getBuffer();
		buffer[0] = isCreateProfile? (byte) 1: (byte) 0;
		apdu.setOutgoingAndSend((short) 0, (short) (1));
		
	}
	
	
	public void showInformation(APDU apdu) {
		if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }
                byte[] decryptedData= new byte[encryptedData.length];
				aesUtils.doDecryptAesCipher(encryptedData, decryptedData);
		short toSend = (short) originLength;

        apdu.setOutgoing();
        apdu.setOutgoingLength(toSend);
        apdu.sendBytesLong(decryptedData, (short)0, toSend);

	}
	
	public void createPin(APDU apdu,byte[] buf) {
		// if(!pin.isValidated()) {
			 // ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
			 // return;
		 // }
		JCSystem.beginTransaction();

		// byte[] decryptAvatar = decrypt(avatar,avatarLength);
		short dataOffset = apdu.getOffsetCdata();
		short datalength = apdu.getIncomingLength();
		byte[] newPin = new byte[datalength];
		Util.arrayCopy(buf,dataOffset,newPin,(short)0,(short)datalength);
		byte[] keyBytes1;
		try {
			keyBytes1 = JCSystem.makeTransientByteArray((short) LENGTH_BLOCK_AES, JCSystem.CLEAR_ON_DESELECT);
		} catch (SystemException e) {
			keyBytes1 = new byte[(short)LENGTH_BLOCK_AES];
		}
            // HMacSHA512.computeHmacSha512(newPin,(short)0x00,(short)newPin.length,keyBytes,(short)0);
            short shalen = sha.doFinal(newPin, (short)0,(short)newPin.length, keyBytes1, (short)0);
            // aesKey.setKey(keyBytes1, (short) 0);
            changeAesKey(keyBytes1);
        
        pin.update(newPin,(short)0,(byte)newPin.length);
		//
		//
		byte[] dataEncrypt;
	
		isNewUser= (byte)'0';
		pin.check(newPin,(short)0,(byte)newPin.length);
		JCSystem.commitTransaction();
	}
	
	public void resetPin(APDU apdu) {
		if (!pin.isValidated()) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
        }
		JCSystem.beginTransaction();
		// byte[] decryptUserId = decrypt(userId,userIdLength);
		
		byte[] hashed= new byte[16];
		sha.doFinal(PIN_INIT_VALUE,(short)0,(short)PIN_INIT_VALUE.length,hashed,(short)0);
		changeAesKey(hashed);
	}
	private void changeAesKey(byte[] newAesKey){
		byte[] tmpDecrypt = new byte[encryptedData.length];
		aesUtils.doDecryptAesCipher(encryptedData,tmpDecrypt);
        aesUtils.setAesKey(newAesKey);
        encryptedData= new byte[tmpDecrypt.length];
        aesUtils.doEncryptAesCipher(tmpDecrypt,encryptedData);
	}
    
    private void rsaSign(APDU apdu,byte[] buf)
	{
		short dataOffset = apdu.getOffsetCdata();
		short datalength = apdu.getIncomingLength();
		RSAPrivateKey rsaPrivKey = decryptPrivKey();
		rsaSig.init(rsaPrivKey, Signature.MODE_SIGN);
		rsaSig.sign(buf, dataOffset, (short)(datalength),sig_buffer, (short)0);
		apdu.setOutgoing();
		apdu.setOutgoingLength(sigLen);

		apdu.sendBytesLong(sig_buffer, (short)0, sigLen);
	}
	
	
	private void exportPublicModulus(APDU apdu) {
		byte buffer[] = apdu.getBuffer();
		short expLenmo = rsaPubKey.getModulus(buffer, (short) 0);
		apdu.setOutgoingAndSend((short) 0, (short) (expLenmo));
	}
	
	private void exportPublicExponent(APDU apdu) {
		byte buffer[] = apdu.getBuffer();
		short expLenex = rsaPubKey.getExponent(buffer, (short) 0);
		apdu.setOutgoingAndSend((short) 0, (short) expLenex);
	}
	
	private void verify(APDU apdu,byte[] buf,byte length) {
		if ( pin.check(buf, ISO7816.OFFSET_CDATA,length) == false ) {
			byte[] count = new byte[1];
			byte remaining = pin.getTriesRemaining();
			count[0]= remaining;
			
			short le = apdu.setOutgoing();
			apdu.setOutgoingLength((short)1);
			apdu.sendBytesLong(count, (short)0, (short)1);
			ISOException.throwIt(SW_VERIFICATION_FAILED);
		}

			byte[] status = new byte[1];
			status[0] = 0x01;
			short le = apdu.setOutgoing();
			apdu.setOutgoingLength((short)1);
			apdu.sendBytesLong(status, (short)0, (short)1);
	}
	public void sendLongApdu(APDU apdu,byte[] data){
	            short toSend = (short) data.length;

        apdu.setOutgoing();
        apdu.setOutgoingLength(toSend);
        apdu.sendBytesLong(data, (short)0, toSend);
    }
    
    public void encryptPrivKey(RSAPrivateKey rsaPrivKey){
	    rsaPrivKeyEncrypted= new byte [256];
		privExponentLength = rsaPrivKey.getExponent(rsaPrivKeyEncrypted, (short) 0);
		 privModulusLength = rsaPrivKey.getModulus(rsaPrivKeyEncrypted, (short) 128);
		byte[] temp = new byte[256];
		aesUtils.doEncryptAesCipher(rsaPrivKeyEncrypted,temp);
		Util.arrayCopy(temp,(short)0,rsaPrivKeyEncrypted,(short)0,(short)256);
		
    }    
    public RSAPrivateKey decryptPrivKey(){
    	RSAPrivateKey rsaPrivKey =(RSAPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE,(short)(8*sigLen),false);
		byte[] rsaPrivKeyDecrypted = new byte[256];
		aesUtils.doEncryptAesCipher(rsaPrivKeyEncrypted,rsaPrivKeyDecrypted);
		rsaPrivKey.setExponent(rsaPrivKeyDecrypted,(short)0,(short)128);
		rsaPrivKey.setModulus(rsaPrivKeyDecrypted,(short)128,(short)128);
		return rsaPrivKey;
    }
}



