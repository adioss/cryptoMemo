package com.adioss.security.symmetric;

import com.adioss.security.Utils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

import static com.adioss.security.symmetric.SymmetricEncryptConstant.INPUT;

public class PBEEncryptor {

    private static final String PBE_ALGORITHM = "PBEWithMD5AndDES";

    public static byte[] encrypt(String plaintext, String password, byte[] salt, int iterationCount) throws Exception {
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, iterationCount);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(PBE_ALGORITHM);
        SecretKey secretKey = keyFactory.generateSecret(keySpec);
        Cipher cipher = Cipher.getInstance(PBE_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new PBEParameterSpec(salt, iterationCount));
        return cipher.doFinal(plaintext.getBytes());
    }

    public static byte[] decrypt(byte[] cipherText, String password, byte[] salt, int iterationCount) throws Exception {
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, iterationCount);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(PBE_ALGORITHM);
        SecretKey secretKey = keyFactory.generateSecret(keySpec);
        Cipher cipher = Cipher.getInstance(PBE_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new PBEParameterSpec(salt, iterationCount));
        return cipher.doFinal(cipherText);
    }

    /**
     * Triple DES: encrypt, decrypt, encrypt. Here, encrypt with DES, decrypt with PBE
     */
    public static void simulateOneDESStep() throws Exception {
        byte[] keyBytes = new byte[]{
                0x73, 0x2f, 0x2d, 0x33, (byte) 0xc8, 0x01, 0x73,
                0x2b, 0x72, 0x06, 0x75, 0x6c, (byte) 0xbd, 0x44,
                (byte) 0xf9, (byte) 0xc1, (byte) 0xc1, 0x03, (byte) 0xdd,
                (byte) 0xd9, 0x7c, 0x7c, (byte) 0xbe, (byte) 0x8e};
        byte[] ivBytes = new byte[]{(byte) 0xb0, 0x7b, (byte) 0xf5, 0x22, (byte) 0xc8, (byte) 0xd6, 0x08, (byte) 0xb8};

        // encrypt the data using precalculated keys
        Cipher cipherEncrypt = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipherEncrypt.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "DESede"), new IvParameterSpec(ivBytes));
        byte[] cipherText = cipherEncrypt.doFinal(INPUT);

        // decrypt the data using PBE
        char[] password = "password".toCharArray();
        byte[] salt = new byte[]{0x7d, 0x60, 0x43, 0x5f, 0x02, (byte) 0xe9, (byte) 0xe0, (byte) 0xae};
        int iterationCount = 2048;
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, iterationCount);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndTripleDES");
        Cipher cipherDecrypt = Cipher.getInstance("PBEWithMD5AndTripleDES");
        Key secretKey = secretKeyFactory.generateSecret(pbeKeySpec);
        cipherDecrypt.init(Cipher.DECRYPT_MODE, secretKey);
        System.out.println("cipher : " + Utils.toHex(cipherText));
        System.out.println("gen key: " + Utils.toHex(secretKey.getEncoded()));
        System.out.println("gen iv : " + Utils.toHex(cipherDecrypt.getIV()));
        System.out.println("plain  : " + Utils.toHex(cipherDecrypt.doFinal(cipherText)));
    }

    public static void test(String[] args) throws Exception {

        byte[] input = new byte[]{
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
        byte[] keyBytes = new byte[]{
                0x73, 0x2f, 0x2d, 0x33, (byte) 0xc8, 0x01, 0x73,
                0x2b, 0x72, 0x06, 0x75, 0x6c, (byte) 0xbd, 0x44,
                (byte) 0xf9, (byte) 0xc1, (byte) 0xc1, 0x03, (byte) 0xdd,
                (byte) 0xd9, 0x7c, 0x7c, (byte) 0xbe, (byte) 0x8e};
        byte[] ivBytes = new byte[]{
                (byte) 0xb0, 0x7b, (byte) 0xf5, 0x22, (byte) 0xc8,
                (byte) 0xd6, 0x08, (byte) 0xb8};

        // encrypt the data using precalculated keys
        Cipher cEnc = Cipher.getInstance("DESede/CBC/PKCS7Padding", "BC");
        cEnc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "DESede"), new IvParameterSpec(ivBytes));
        byte[] out = cEnc.doFinal(input);

        // decrypt the data using PBE
        char[] password = "password".toCharArray();
        byte[] salt = new byte[]{0x7d, 0x60, 0x43, 0x5f, 0x02, (byte) 0xe9, (byte) 0xe0, (byte) 0xae};
        int iterationCount = 2048;
        PBEKeySpec pbeSpec = new PBEKeySpec(password, salt, iterationCount);
        SecretKeyFactory keyFact = SecretKeyFactory.getInstance("PBEWithSHAAnd3KeyTripleDES", "BC");
        Cipher cDec = Cipher.getInstance("PBEWithSHAAnd3KeyTripleDES", "BC");
        Key sKey = keyFact.generateSecret(pbeSpec);
        cDec.init(Cipher.DECRYPT_MODE, sKey);

        System.out.println("cipher : " + Utils.toHex(out));
        System.out.println("gen key: " + Utils.toHex(sKey.getEncoded()));
        System.out.println("gen iv : " + Utils.toHex(cDec.getIV()));
        System.out.println("plain  : " + Utils.toHex(cDec.doFinal(out)));
    }


    public static void main(String[] args) throws Exception {
        simulateOneDESStep();
    }
}
