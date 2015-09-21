package com.adioss.security.symmetric.block;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

import static com.adioss.security.symmetric.SymmetricEncryptTools.*;

public class ModeForSymmetricEncryption {
    /**
     * Symmetric encrypt by block with ECB mode: PKCS7 Padding using DES cipher
     * Problem: show that we can discovering patterns
     */
    private static void encryptWithECB() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, ShortBufferException, BadPaddingException, IllegalBlockSizeException {
        System.out.println("encryptWithECB");
        byte[] keyBytes = new byte[]{0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef};

        SecretKeySpec key = new SecretKeySpec(keyBytes, "DES");
        // here ECB
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS7Padding", "BC");

        simpleEncryptDecrypt(INPUT, key, cipher);
        // print cipher: 3260266c2cf202e28325790654a444d93260266c2cf202e2086f9a1d74c94d4e bytes: 32
        // we can see that 3260266c2cf202e2 is printed two times: same encryption pattern discovery
    }

    /**
     * Symmetric encrypt by block with CBC mode: PKCS7 Padding using DES cipher and IV
     */
    private static void encryptWithCBC() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, ShortBufferException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        System.out.println("encryptWithCBC");
        byte[] keyBytes = new byte[]{0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef};
        byte[] ivBytes = new byte[]{0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};

        SecretKeySpec key = new SecretKeySpec(keyBytes, "DES");
        // used to init cipher
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS7Padding", "BC");

        encryptDecryptWithIV(INPUT, key, ivSpec, cipher);
    }

    /**
     * Symmetric encrypt by block with CBC mode: PKCS7 Padding using DES cipher and secure random IV
     */
    private static void encryptWithCBCWithSecureRandomIV() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, ShortBufferException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        System.out.println("encryptWithCBCWithSecureRandomIV");
        byte[] keyBytes = new byte[]{0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef};
        byte[] ivBytes = new byte[8];

        SecretKeySpec key = new SecretKeySpec(keyBytes, "DES");
        // used to init cipher
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(ivBytes);
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS7Padding", "BC");
        // secure random can be done by calling cipher method too
        // see => IvParameterSpec ivSpec = new IvParameterSpec(cipher.getIV());
        encryptDecryptWithIV(INPUT, key, ivSpec, cipher);
    }


    /**
     * Symmetric encrypt by block with CTS mode: no padding using DES cipher and IV
     */
    private static void encryptWithCTS() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, ShortBufferException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        System.out.println("encryptWithCTS");
        byte[] keyBytes = new byte[]{0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef};
        byte[] ivBytes = new byte[]{0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};

        SecretKeySpec key = new SecretKeySpec(keyBytes, "DES");
        // used to init cipher
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        Cipher cipher = Cipher.getInstance("DES/CTS/NoPadding", "BC");

        encryptDecryptWithIV(INPUT, key, ivSpec, cipher);
    }

    /**
     * Symmetric encrypt by block with CTR mode: no padding using DES cipher and IV
     */
    private static void encryptWithCTR() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, ShortBufferException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        System.out.println("encryptWithCBC");
        byte[] keyBytes = new byte[]{0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef};
        byte[] ivBytes = new byte[]{0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};

        SecretKeySpec key = new SecretKeySpec(keyBytes, "DES");
        // used to init cipher
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        Cipher cipher = Cipher.getInstance("DES/CTR/NoPadding", "BC");

        encryptDecryptWithIV(INPUT, key, ivSpec, cipher);
    }

    public static void main(String[] args) throws Exception {
        encryptWithECB();
        encryptWithCBC();
        encryptWithCBCWithSecureRandomIV();
        encryptWithCTS();
        encryptWithCTR();
    }
}