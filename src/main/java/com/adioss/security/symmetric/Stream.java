package com.adioss.security.symmetric;

import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.adioss.security.Utils;

class Stream {
    private static final Logger LOG = LoggerFactory.getLogger(Stream.class);

    static void streamEncryptDecrypt() throws Exception {

        byte[] input = new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04,
                0x05, 0x06};

        byte[] keyBytes = new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

        byte[] ivBytes = Utils.generateSecureRandomBytes(16);

        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        LOG.debug("input : " + Utils.toHex(input));

        // encryption pass
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);

        byte[] cipherText;
        try (CipherInputStream cipherInputStream = new CipherInputStream(new ByteArrayInputStream(input), cipher);
             ByteArrayOutputStream byteArrayOutputStream1 = new ByteArrayOutputStream()) {
            int character;
            while ((character = cipherInputStream.read()) >= 0) {
                byteArrayOutputStream1.write(character);
            }
            cipherText = byteArrayOutputStream1.toByteArray();
            LOG.debug("cipher: " + Utils.toHex(cipherText));
        }

        // decryption pass
        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);

        try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
             CipherOutputStream cipherOutputStream = new CipherOutputStream(byteArrayOutputStream, cipher)) {
            cipherOutputStream.write(cipherText);
            LOG.debug("plain: " + Utils.toHex(byteArrayOutputStream.toByteArray()));
        }
    }

    private Stream() {
    }
}
