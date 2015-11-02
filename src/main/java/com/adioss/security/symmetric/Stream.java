package com.adioss.security.symmetric;

import com.adioss.security.Utils;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class Stream {
    public static void streamEncryptDecrypt() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {
        byte[] input = new byte[]{
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
        byte[] keyBytes = new byte[]{
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

        byte[] ivBytes = new byte[]{
                0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        System.out.println("input : " + Utils.toHex(input));

        // encryption pass
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
        CipherInputStream cipherInputStream = new CipherInputStream(new ByteArrayInputStream(input), cipher);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        int character;
        while ((character = cipherInputStream.read()) >= 0) {
            byteArrayOutputStream.write(character);
        }
        byte[] cipherText = byteArrayOutputStream.toByteArray();
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
