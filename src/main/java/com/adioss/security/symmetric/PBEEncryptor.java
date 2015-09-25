package com.adioss.security.symmetric;

import com.adioss.security.Utils;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

public class PBEEncryptor {
    /**
     * Triple DES: encrypt, decrypt, encrypt. Here, encrypt with DES, decrypt with PBE
     */
    private static void simulateOneDESStep() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeySpecException {
        byte[] keyBytes = new byte[]{
                0x73, 0x2f, 0x2d, 0x33, (byte) 0xc8, 0x01, 0x73,
                0x2b, 0x72, 0x06, 0x75, 0x6c, (byte) 0xbd, 0x44,
                (byte) 0xf9, (byte) 0xc1, (byte) 0xc1, 0x03, (byte) 0xdd,
                (byte) 0xd9, 0x7c, 0x7c, (byte) 0xbe, (byte) 0x8e};
        byte[] ivBytes = new byte[]{(byte) 0xb0, 0x7b, (byte) 0xf5, 0x22, (byte) 0xc8, (byte) 0xd6, 0x08, (byte) 0xb8};

        // encrypt the data using precalculated keys
        Cipher cipherEncrypt = Cipher.getInstance("DESede/CBC/PKCS7Padding", "BC");
        cipherEncrypt.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "DESede"), new IvParameterSpec(ivBytes));
        byte[] cipherText = cipherEncrypt.doFinal(SymmetricEncryptTools.INPUT);

        // decrypt the data using PBE
        char[] password = "password".toCharArray();
        byte[] salt = new byte[]{0x7d, 0x60, 0x43, 0x5f, 0x02, (byte) 0xe9, (byte) 0xe0, (byte) 0xae};
        int iterationCount = 2048;
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, iterationCount);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithSHAAnd3KeyTripleDES", "BC");
        Cipher cipherDecrypt = Cipher.getInstance("PBEWithSHAAnd3KeyTripleDES", "BC");
        Key secretKey = secretKeyFactory.generateSecret(pbeKeySpec);
        cipherDecrypt.init(Cipher.DECRYPT_MODE, secretKey);
        System.out.println("cipher : " + Utils.toHex(cipherText));
        System.out.println("gen key: " + Utils.toHex(secretKey.getEncoded()));
        System.out.println("gen iv : " + Utils.toHex(cipherDecrypt.getIV()));
        System.out.println("plain  : " + Utils.toHex(cipherDecrypt.doFinal(cipherText)));
    }

    public static void main(String[] args) throws Exception {
        simulateOneDESStep();
    }
}
