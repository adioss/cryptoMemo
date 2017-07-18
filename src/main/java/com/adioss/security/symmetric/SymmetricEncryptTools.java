package com.adioss.security.symmetric;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.adioss.security.Utils;

public final class SymmetricEncryptTools {
    private static final Logger LOG = LoggerFactory.getLogger(SymmetricEncryptTools.class);

    public static void simpleEncryptDecrypt(byte[] input, Key key, Cipher cipher)
            throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        LOG.debug("input : " + Utils.toHex(input));
        // encryption pass
        cipher.init(Cipher.ENCRYPT_MODE, key);
        // need to get cipher text size
        byte[] cipherText = new byte[cipher.getOutputSize(input.length)];
        int cipherTextLength = cipher.update(input, 0, input.length, cipherText, 0);
        cipherTextLength += cipher.doFinal(cipherText, cipherTextLength);
        LOG.debug("cipher: " + Utils.toHex(cipherText) + " bytes: " + cipherTextLength);

        // decryption pass
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] plainText = new byte[cipher.getOutputSize(cipherTextLength)];
        int plainTextLength = cipher.update(cipherText, 0, cipherTextLength, plainText, 0);
        plainTextLength += cipher.doFinal(plainText, plainTextLength);
        LOG.debug("plain : " + Utils.toHex(plainText) + " bytes: " + plainTextLength);
    }

    public static void encryptDecryptWithIV(byte[] input, SecretKeySpec key, IvParameterSpec ivSpec, Cipher cipher)
            throws InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        LOG.debug("input : " + Utils.toHex(input));
        // encryption pass
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] cipherText = new byte[cipher.getOutputSize(input.length)];
        int cipherTextLength = cipher.update(input, 0, input.length, cipherText, 0);
        cipherTextLength += cipher.doFinal(cipherText, cipherTextLength);
        LOG.debug("cipher: " + Utils.toHex(cipherText, cipherTextLength) + " bytes: " + cipherTextLength);

        // decryption pass
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] plainText = new byte[cipher.getOutputSize(cipherTextLength)];
        int plainTextLength = cipher.update(cipherText, 0, cipherTextLength, plainText, 0);
        plainTextLength += cipher.doFinal(plainText, plainTextLength);
        LOG.debug("plain : " + Utils.toHex(plainText, plainTextLength) + " bytes: " + plainTextLength);
    }

    private SymmetricEncryptTools() {
    }
}
