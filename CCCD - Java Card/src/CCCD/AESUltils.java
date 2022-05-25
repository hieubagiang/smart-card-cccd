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

    
    
    public void doEncryptAesCipher(APDU apdu, byte[] arr, short len) {
        try {
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
    
    
    
}
