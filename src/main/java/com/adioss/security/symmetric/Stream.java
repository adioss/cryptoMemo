package com.adioss.security.symmetric;

import com.adioss.security.Utils;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

public class Stream {
    static void streamEncryptDecrypt() throws Exception {
        ByteArrayOutputStream byteArrayOutputStream;

        byte[] input = new byte[]{
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};

        byte[] keyBytes = new byte[]{
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
        };

        byte[] ivBytes = new byte[]{
                0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        System.out.println("input : " + Utils.toHex(input));

        // encryption pass
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
        CipherInputStream cipherInputStream = new CipherInputStream(new ByteArrayInputStream(input), cipher);
        ByteArrayOutputStream byteArrayOutputStream1 = new ByteArrayOutputStream();
        int character;
        while ((character = cipherInputStream.read()) >= 0) {
            byteArrayOutputStream1.write(character);
        }
        byte[] cipherText = byteArrayOutputStream1.toByteArray();
        System.out.println("cipher: " + Utils.toHex(cipherText));

        // decryption pass
        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        byteArrayOutputStream = new ByteArrayOutputStream();
        try (CipherOutputStream cipherOutputStream = new CipherOutputStream(byteArrayOutputStream, cipher)) {
            cipherOutputStream.write(cipherText);
        }
        System.out.println("plain: " + Utils.toHex(byteArrayOutputStream.toByteArray()));
    }

    public static void main(String[] args) throws Exception {
        streamEncryptDecrypt();
    }

}
