package com.adioss.security.symmetric;

import java.security.Key;
import javax.crypto.*;
import javax.crypto.spec.*;
import com.adioss.security.Utils;

import static com.adioss.security.symmetric.SymmetricEncryptConstant.INPUT;

public class KeyGeneration {
    /**
     * Use {@link KeyGenerator} to create a key
     */
    static void encryptWithKeyGenerator() throws Exception {
        byte[] ivBytes = Utils.generateSecureRandomBytes(16);
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(128);
        Key encryptionKey = generator.generateKey();
        System.out.println("key     : " + Utils.toHex(encryptionKey.getEncoded()));
        System.out.println("input   : " + Utils.toHex(INPUT));

        // encryption pass
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, new IvParameterSpec(ivBytes));
        byte[] cipherText = new byte[cipher.getOutputSize(INPUT.length)];
        int cipherTextLength = cipher.update(INPUT, 0, INPUT.length, cipherText, 0);
        cipherTextLength += cipher.doFinal(cipherText, cipherTextLength);

        // create our decryption key using information
        // extracted from the encryption key
        Key decryptionKey = new SecretKeySpec(encryptionKey.getEncoded(), encryptionKey.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, decryptionKey, new IvParameterSpec(ivBytes));
        byte[] plainText = new byte[cipher.getOutputSize(cipherTextLength)];
        int plainTextLength = cipher.update(cipherText, 0, cipherTextLength, plainText, 0);
        plainTextLength += cipher.doFinal(plainText, plainTextLength);
        System.out.println("plain   : " + Utils.toHex(plainText, plainTextLength) + " bytes: " + plainTextLength);
    }

    public static void main(String[] args) throws Exception {
        encryptWithKeyGenerator();
    }

    private KeyGeneration() {
    }
}
