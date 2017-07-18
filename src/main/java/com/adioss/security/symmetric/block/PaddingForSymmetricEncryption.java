package com.adioss.security.symmetric.block;

import javax.crypto.*;
import javax.crypto.spec.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.adioss.security.Utils;
import com.google.common.annotations.VisibleForTesting;

class PaddingForSymmetricEncryption {
    private static final Logger LOG = LoggerFactory.getLogger(PaddingForSymmetricEncryption.class);

    /**
     * Symmetric encrypt by block with PKCS7 padding
     */
    @VisibleForTesting
    static void encryptWithPadding() throws Exception {
        byte[] input = new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
                0x15, 0x16, 0x17};
        byte[] keyBytes = new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        // here select PKCS7 padding
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
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

    private PaddingForSymmetricEncryption() {
    }
}
