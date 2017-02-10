package com.adioss.security.symmetric;

import javax.crypto.*;
import javax.crypto.spec.*;

class PBEEncryption {

    private static final String PBE_ALGORITHM = "PBEWithMD5AndDES";

    static byte[] encrypt(String plaintext, String password, byte[] salt, int iterationCount) throws Exception {
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, iterationCount);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(PBE_ALGORITHM);
        SecretKey secretKey = keyFactory.generateSecret(keySpec);
        Cipher cipher = Cipher.getInstance(PBE_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new PBEParameterSpec(salt, iterationCount));
        return cipher.doFinal(plaintext.getBytes());
    }

    static byte[] decrypt(byte[] cipherText, String password, byte[] salt, int iterationCount) throws Exception {
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, iterationCount);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(PBE_ALGORITHM);
        SecretKey secretKey = keyFactory.generateSecret(keySpec);
        Cipher cipher = Cipher.getInstance(PBE_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new PBEParameterSpec(salt, iterationCount));
        return cipher.doFinal(cipherText);
    }
}
