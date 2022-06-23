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
import javacard.security.*;
import javacardx.crypto.*;
public class RSA extends Applet
{
	private static final byte INS_SIGN = (byte)0x00;
	private static final byte INS_VERIFY = (byte)0x01;

	private RSAPrivateKey rsaPrivKey;
	private RSAPublicKey rsaPubKey;
	private Signature rsaSig;
	private byte[] s1, sig_buffer;
	private short sigLen;

	private RSA()
	{
		s1 = new byte[]{0x01, 0x02, 0x03};
	initRsa();
	}
	void initRsa(){
		sigLen = (short)(KeyBuilder.LENGTH_RSA_2048/8);
		sig_buffer = new byte[sigLen];
		if(s1.length>sigLen){
		ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		rsaSig = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1,false);
		rsaPrivKey =(RSAPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE,(short)(8*sigLen),false);
		rsaPubKey =(RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC,(short)(8*sigLen), false);
		KeyPair keyPair = new KeyPair(KeyPair.ALG_RSA,(short)(8*sigLen));
		keyPair.genKeyPair();
		rsaPrivKey = (RSAPrivateKey)keyPair.getPrivate();
		rsaPubKey = (RSAPublicKey)keyPair.getPublic();
	}
	public static void install(byte[] bArray, short bOffset,byte bLength)
	{
		new RSA().register(bArray, (short) (bOffset +1), bArray[bOffset]);
	}
	public void process(APDU apdu)
	{
		if (selectingApplet())
		{
			return;
		}
		byte[] buf = apdu.getBuffer();
		apdu.setIncomingAndReceive();
		switch (buf[ISO7816.OFFSET_INS])
		{
		case INS_SIGN:
			rsaSign(apdu);
			break;
		case INS_VERIFY:
			rsaVerify(apdu);
			break;
		case 0x02:
			getPublicRSA(apdu, (short)0x00);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
	
	private void rsaSign(APDU apdu)
	{
		rsaSig.init(rsaPrivKey, Signature.MODE_SIGN);
		rsaSig.sign(s1, (short)0, (short)(s1.length),sig_buffer, (short)0);
		apdu.setOutgoing();
		apdu.setOutgoingLength(sigLen);
		apdu.sendBytesLong(sig_buffer, (short)0, sigLen);
	}
	private void rsaVerify(APDU apdu)
	{
		byte [] buf = apdu.getBuffer();
		rsaSig.init(rsaPubKey, Signature.MODE_VERIFY);
		boolean ret = rsaSig.verify(s1, (short)0,(short)(s1.length), sig_buffer, (short)0, sigLen);
		buf[(short)0] = ret ? (byte)1 : (byte)0;
		apdu.setOutgoingAndSend((short)0, (short)1);
	}
	
	    private void getPublicRSA(APDU apdu, short choose){

        if (!rsaPubKey.isInitialized())
        {
                ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
        }

        byte[] buffer = apdu.getBuffer();
        short length = 0;

        switch ((short) choose)
        {
        case 0x00:
                length = rsaPubKey.getModulus(buffer, (short)0);
                break;
        case 0x01:
                length = rsaPubKey.getExponent(buffer, (short)0);
                break;
        default:

                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        apdu.setOutgoingAndSend((short)0, length);
        return;
    }
}