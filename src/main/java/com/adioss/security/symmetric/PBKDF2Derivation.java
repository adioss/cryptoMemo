package com.adioss.security.symmetric;

import com.google.common.annotations.VisibleForTesting;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

class PBKDF2Derivation {
    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA384";
    private static final String AES = "AES";
    private static final String AES_CBC_PKCS5_PADDING = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;

    @VisibleForTesting
    static Key deriveKey(String password, byte[] salt, int iterationCount, int keySize) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterationCount, keySize);
        SecretKey secretKey = factory.generateSecret(spec);
        return new SecretKeySpec(secretKey.getEncoded(), AES);
    }

    @VisibleForTesting
    static byte[] encrypt(Key key, byte[] iv, byte[] dataToEncypt) throws Exception {
        Cipher aesCipher = Cipher.getInstance(AES_CBC_PKCS5_PADDING);
        aesCipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
        return aesCipher.doFinal(dataToEncypt);
    }

    @VisibleForTesting
    static byte[] decrypt(Key key, byte[] iv, byte[] dataToDecrypt) throws Exception {
        Cipher aesCipher = Cipher.getInstance(AES_CBC_PKCS5_PADDING);
        aesCipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
        return aesCipher.doFinal(dataToDecrypt);
    }

    private PBKDF2Derivation() {
    }
}
