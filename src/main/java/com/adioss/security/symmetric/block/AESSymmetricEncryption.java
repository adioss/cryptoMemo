package com.adioss.security.symmetric.block;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

public class AESSymmetricEncryption {

    private static final byte[] KEY = hexStringToByteArray("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF");
    private static final byte[] IV = new byte[]{(byte) 0x69, (byte) 0x2b, (byte) 0x74, (byte) 0x34, (byte) 0x02, (byte) 0xb2, (byte) 0xc4, (byte) 0x9e,
            (byte) 0xf9, (byte) 0x44, (byte) 0x99, (byte) 0xc9, (byte) 0x80, (byte) 0x65, (byte) 0xcd, (byte) 0x8f};
    
    private static final byte[] MESSAGE = "Hello!!".getBytes();

    static void encryptDecryptECB() throws Exception {
        SecretKey secretKey = new SecretKeySpec(KEY, "AES");

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encrypted = cipher.doFinal(MESSAGE);
        System.out.println("cipher: " + show(encrypted));

        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] original = cipher.doFinal(encrypted);
        System.out.println("plain: " + show(original) + "        " + new String(original));
    }

    static void encryptDecryptCBC() throws Exception {
        SecretKey secretKey = new SecretKeySpec(KEY, "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(IV));
        byte[] encrypted = cipher.doFinal(MESSAGE);
        System.out.println("cipher: " + show(encrypted));

        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(IV));
        byte[] original = cipher.doFinal(encrypted);
        System.out.println("plain: " + show(original) + "        " + new String(original));
    }

    static void encryptDecryptGCM() throws Exception {
        SecureRandom random = SecureRandom.getInstanceStrong();
        SecretKey secretKey = new SecretKeySpec(KEY, "AES");

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");  // GCM is no padding: NoPadding is here only for convention
        final byte[] iv = new byte[12];
        random.nextBytes(iv);
        GCMParameterSpec spec = new GCMParameterSpec(128, IV);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        byte[] encrypted = cipher.doFinal(MESSAGE);
        System.out.println("cipher: " + show(encrypted));

        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
        byte[] original = cipher.doFinal(encrypted);
        System.out.println("plain: " + show(original) + "        " + new String(original));
    }

    private static String show(byte[] encrypted) {
        String result = "";
        for (byte b : encrypted) {
            result += b + " ";
        }
        return result;
    }

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}
