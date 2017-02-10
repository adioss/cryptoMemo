package com.adioss.security.symmetric;

import java.security.Key;
import javax.crypto.*;
import javax.crypto.spec.*;

class PBKDF2Derivation {
    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA384";
    private static final String AES = "AES";
    private static final String AES_CBC_PKCS5_PADDING = "AES/CBC/PKCS5Padding";

    static Key deriveKey(String password, byte[] salt, int iterationCount, int keySize) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterationCount, keySize);
        SecretKey secretKey = factory.generateSecret(spec);
        return new SecretKeySpec(secretKey.getEncoded(), AES);
    }

    static byte[] encrypt(Key key, byte[] iv, byte[] dataToEncypt) throws Exception {
        Cipher aesCipher = Cipher.getInstance(AES_CBC_PKCS5_PADDING);
        aesCipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        return aesCipher.doFinal(dataToEncypt);
    }

    static byte[] decrypt(Key key, byte[] iv, byte[] dataToDecrypt) throws Exception {
        Cipher aesCipher = Cipher.getInstance(AES_CBC_PKCS5_PADDING);
        aesCipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return aesCipher.doFinal(dataToDecrypt);
    }

    private PBKDF2Derivation() {
    }
}
