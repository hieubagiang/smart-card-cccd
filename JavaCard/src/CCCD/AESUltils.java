package CCCD;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;


/**
 *
 * @author Langl
 */
public class AESUltils {
    private byte[] tempBuffer, aesKey;
    private byte aesKeyLen;
    private Cipher aesCipher;
    private AESKey tempAesKey1;

    public AESUltils() {
        tempBuffer = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);
        //AES
        aesKey = new byte[16];
        aesKeyLen = 0;
    }

    public byte[] getTempBuffer() {
        return tempBuffer;
    }

    public void setTempBuffer(byte[] tempBuffer) {
        this.tempBuffer = tempBuffer;
    }

    public byte[] getAesKey() {
        return aesKey;
    }

    public void setAesKey(byte[] aesKey) {
        this.aesKey = aesKey;
    }

    public byte getAesKeyLen() {
        return aesKeyLen;
    }

    public void setAesKeyLen(byte aesKeyLen) {
        this.aesKeyLen = aesKeyLen;
    }

    public Cipher getAesCipher() {
        return aesCipher;
    }

    public void setAesCipher(Cipher aesCipher) {
        this.aesCipher = aesCipher;
    }

    public AESKey getTempAesKey1() {
        return tempAesKey1;
    }

    public void setTempAesKey1(AESKey tempAesKey1) {
        this.tempAesKey1 = tempAesKey1;
    }
    
        // Set Pin as AES Key 
    public void setAesKey(APDU apdu, short len) {
        byte[] buffer = apdu.getBuffer();
        byte keyLen = 4;
        if (len < 4) // The length of key is 16 bytes
        {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        //Copy the incoming AES Key value to the global variable 'aesKey'
        JCSystem.beginTransaction();
        Util.arrayCopy(aesKey, (short) 0, aesKey, (short) 0, (short) 4);
        aesKeyLen = keyLen;
        JCSystem.commitTransaction();
    }

// 223 / 16 = ? index 0 ??? m ? nhng length 
    public byte[] paddingArray(byte[] arr, short len) {
    	  short previousLen = (short) len;
            if (len >= 0 && len % 16 != 0) {
            	len += (16 - (len % 16));
            	
            }
            byte[] newArr = new byte[len];
            // cái này d dài copy = len - pre - 1 thôi 
             Util.arrayCopyNonAtomic(arr,(short) 0,  newArr, (short) 0, previousLen);
            // Util.arrayFillNonAtomic(arr, (short) previousLen, (short) (len-previousLen), (byte) 0);
          return newArr;
    }    
    
    public void doEncryptAesCipher(APDU apdu, byte[] arr) {
        try {
        	short len = (short) arr.length;
            byte[] buffer = apdu.getBuffer();
            aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
            tempAesKey1 = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
            if (len <= 0 || len % 16 != 0) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
               
            }
            tempAesKey1.setKey(aesKey, (short) 0);

            aesCipher.init(tempAesKey1, Cipher.MODE_ENCRYPT);

            aesCipher.doFinal(arr, (short) 0, len, buffer, (short) 0);
            Util.arrayCopy(buffer, (short) 0, arr, (short) 0, len);

        } catch (CryptoException e) {
            short reason = e.getReason();
            ISOException.throwIt(reason);
        }
    }
    
    
    public void doEncryptAesCipher(byte[] arr,byte[] outBuffer) {
        try {
        	short len = (short) arr.length;
            aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
            tempAesKey1 = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
            if (len <= 0 || len % 16 != 0) {
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
               
            }
            tempAesKey1.setKey(aesKey, (short) 0);
            aesCipher.init(tempAesKey1, Cipher.MODE_ENCRYPT);
            aesCipher.doFinal(arr, (short) 0, len, outBuffer, (short) 0);

        } catch (CryptoException e) {
            short reason = e.getReason();
            ISOException.throwIt(reason);
        }
    }
    public void doDecryptAesCipher(byte[] encrypted,byte[] outBuffer) {
        try {
            aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
            tempAesKey1 = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
            tempAesKey1.setKey(aesKey, (short) 0);
            aesCipher.init(tempAesKey1, Cipher.MODE_DECRYPT);
            aesCipher.doFinal(encrypted, (short) 0,(short) encrypted.length, outBuffer, (short) 0);

        } catch (CryptoException e) {
            short reason = e.getReason();
            ISOException.throwIt(reason);
        }
    } 
}
