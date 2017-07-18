package com.adioss.security.symmetric.block;

import java.security.SecureRandom;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.annotations.VisibleForTesting;

class AESSymmetricEncryption {
    private static final Logger LOG = LoggerFactory.getLogger(AESSymmetricEncryption.class);
    private static final byte[] KEY = new byte[]{(byte) 0x69, (byte) 0x69, (byte) 0x2b, (byte) 0x74, (byte) 0x9e, (byte) 0x80, (byte) 0x80, (byte) 0x65,
            (byte) 0x74, (byte) 0x65, (byte) 0x9e, (byte) 0x99, (byte) 0x99, (byte) 0x99, (byte) 0x74, (byte) 0x99,};
    private static final byte[] IV = new byte[]{(byte) 0x69, (byte) 0x2b, (byte) 0x74, (byte) 0x34, (byte) 0x02, (byte) 0xb2, (byte) 0xc4, (byte) 0x9e,
            (byte) 0xf9, (byte) 0x44, (byte) 0x99, (byte) 0xc9, (byte) 0x80, (byte) 0x65, (byte) 0xcd, (byte) 0x8f};

    private static final byte[] MESSAGE = "Hello!!".getBytes();

    @VisibleForTesting
    static void encryptDecryptECB() throws Exception {
        SecretKey secretKey = new SecretKeySpec(KEY, "AES");

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encrypted = cipher.doFinal(MESSAGE);
        LOG.debug("cipher: " + show(encrypted));

        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] original = cipher.doFinal(encrypted);
        LOG.debug("plain: " + show(original) + "        " + new String(original));
    }

    @VisibleForTesting
    static void encryptDecryptCBC() throws Exception {
        SecretKey secretKey = new SecretKeySpec(KEY, "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(IV));
        byte[] encrypted = cipher.doFinal(MESSAGE);
        LOG.debug("cipher: " + show(encrypted));

        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(IV));
        byte[] original = cipher.doFinal(encrypted);
        LOG.debug("plain: " + show(original) + "        " + new String(original));
    }

    @VisibleForTesting
    static void encryptDecryptGCM() throws Exception {
        SecureRandom random = SecureRandom.getInstanceStrong();
        SecretKey secretKey = new SecretKeySpec(KEY, "AES");

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");  // GCM is no padding: NoPadding is here only for convention
        final byte[] iv = new byte[12];
        random.nextBytes(iv);
        GCMParameterSpec spec = new GCMParameterSpec(128, IV);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        byte[] encrypted = cipher.doFinal(MESSAGE);
        LOG.debug("cipher: " + show(encrypted));

        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
        byte[] original = cipher.doFinal(encrypted);
        LOG.debug("plain: " + show(original) + "        " + new String(original));
    }

    private static String show(byte[] encrypted) {
        String result = "";
        for (byte b : encrypted) {
            result += b + " ";
        }
        return result;
    }

    private AESSymmetricEncryption() {
    }
}
