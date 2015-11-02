package com.adioss.security.symmetric;

import com.adioss.security.Utils;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Random;

public class PBEEncryptor {

    public static final String PASSWORD = "password";

    public static String encryptPBE(String input) throws Exception {
        byte[] inputBytes = input.getBytes();
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        PBEKeySpec pbeKeySpec = new PBEKeySpec(PASSWORD.toCharArray());
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndTripleDES");
        SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);

        byte[] salt = new byte[8];
        Random random = new Random();
        random.nextBytes(salt);

        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, 100);
        Cipher cipher = Cipher.getInstance("PBEWithMD5AndTripleDES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, pbeParameterSpec);
        byteArrayOutputStream.write(salt);
        byteArrayOutputStream.write(cipher.update(inputBytes, 0, inputBytes.length));
        byte[] output = cipher.doFinal();
        return new String(output);
    }

    public static String asHex(byte buf[]) {
        StringBuffer strbuf = new StringBuffer(buf.length * 2);
        int i;

        for (i = 0; i < buf.length; i++) {
            if (((int) buf[i] & 0xff) < 0x10)
                strbuf.append("0");

            strbuf.append(Long.toString((int) buf[i] & 0xff, 16));
        }

        return strbuf.toString();
    }

    public static void test() throws Exception {
        String message = "This is just an example";
        // Get the KeyGenerator
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(128); // 192 and 256 bits may not be available
        // Generate the secret key specs.
        SecretKey skey = kgen.generateKey();
        byte[] raw = skey.getEncoded();
        SecretKeySpec skeySpec = new SecretKeySpec(raw, "AES");


        // Instantiate the cipher
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        byte[] encrypted = cipher.doFinal((message).getBytes());
        System.out.println("encrypted string: " + asHex(encrypted));

        cipher.init(Cipher.DECRYPT_MODE, skeySpec);
        byte[] original = cipher.doFinal(encrypted);
        String originalString = new String(original);
        System.out.println("Original string: " + originalString);
    }

    private static String decryptPBE(byte[] bytes) throws Exception {
        PBEKeySpec pbeKeySpec = new PBEKeySpec(PASSWORD.toCharArray());
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndTripleDES");
        SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);

        byte[] salt = Arrays.copyOfRange(bytes, 0, 8);
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, 100);
        Cipher cipher = Cipher.getInstance("PBEWithMD5AndTripleDES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, pbeParameterSpec);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();


        byteArrayOutputStream.write(cipher.update(bytes, 0, bytes.length));

        byte[] output = cipher.doFinal();
        if (output != null) {
            byteArrayOutputStream.write(output);
        }
        return new String(byteArrayOutputStream.toByteArray());
    }

    public static void main(String[] args) throws Exception {
//        simulateOneDESStep();
//        String encryptPBE = encryptPBE("my text that I need to encrypt with PBE");
//        System.out.println(encryptPBE);
//        String decrypted = decryptPBE(encryptPBE.getBytes());
//        System.out.println(decrypted);
        test();
    }

    /**
     * Triple DES: encrypt, decrypt, encrypt. Here, encrypt with DES, decrypt with PBE
     */
    public static void simulateOneDESStep() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        byte[] keyBytes = new byte[]{
                0x73, 0x2f, 0x2d, 0x33, (byte) 0xc8, 0x01, 0x73,
                0x2b, 0x72, 0x06, 0x75, 0x6c, (byte) 0xbd, 0x44,
                (byte) 0xf9, (byte) 0xc1, (byte) 0xc1, 0x03, (byte) 0xdd,
                (byte) 0xd9, 0x7c, 0x7c, (byte) 0xbe, (byte) 0x8e};
        byte[] ivBytes = new byte[]{(byte) 0xb0, 0x7b, (byte) 0xf5, 0x22, (byte) 0xc8, (byte) 0xd6, 0x08, (byte) 0xb8};

        // encrypt the data using precalculated keys
        Cipher cipherEncrypt = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipherEncrypt.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "DESede"), new IvParameterSpec(ivBytes));
        byte[] cipherText = cipherEncrypt.doFinal(SymmetricEncryptTools.INPUT);

        // decrypt the data using PBE
        char[] password = "password".toCharArray();
        byte[] salt = new byte[]{0x7d, 0x60, 0x43, 0x5f, 0x02, (byte) 0xe9, (byte) 0xe0, (byte) 0xae};
        int iterationCount = 2048;
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, iterationCount);
//        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithSHAAnd3KeyTripleDES");
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndDES");
        Cipher cipherDecrypt = Cipher.getInstance("PBEWithMD5AndDES");
        Key secretKey = secretKeyFactory.generateSecret(pbeKeySpec);
        cipherDecrypt.init(Cipher.DECRYPT_MODE, secretKey, cipherEncrypt.getParameters());
        System.out.println("cipher : " + Utils.toHex(cipherText));
        System.out.println("gen key: " + Utils.toHex(secretKey.getEncoded()));
        System.out.println("gen iv : " + Utils.toHex(cipherDecrypt.getIV()));
        System.out.println("plain  : " + Utils.toHex(cipherDecrypt.doFinal(cipherText)));
    }
}
