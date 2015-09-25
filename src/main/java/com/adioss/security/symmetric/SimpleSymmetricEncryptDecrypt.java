package com.adioss.security.symmetric;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

/**
 * Simple symmetric test with input/output files. Best entry point to show how symmetric crypto works.
 * {@see com.adioss.security.symmetric.SimpleSymmetricEncryptDecryptTest}
 */
public class SimpleSymmetricEncryptDecrypt {

    public void encrypt(File inputFile, File outputFile, byte[] key, String algorithm, String transformation) {
        doCrypto(inputFile, outputFile, Cipher.ENCRYPT_MODE, key, algorithm, transformation);
    }

    public void decrypt(File inputFile, File outputFile, byte[] key, String algorithm, String transformation) {
        doCrypto(inputFile, outputFile, Cipher.DECRYPT_MODE, key, algorithm, transformation);
    }

    private static void doCrypto(File inputFile, File outputFile, int cipherMode, byte[] key, String algorithm, String transformation) {
        try {
            Key secretKey = new SecretKeySpec(key, algorithm);
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(cipherMode, secretKey);

            try (FileInputStream inputStream = new FileInputStream(inputFile); FileOutputStream outputStream = new FileOutputStream(outputFile)) {
                byte[] inputBytes = new byte[(int) inputFile.length()];
                inputStream.read(inputBytes);
                byte[] outputBytes = cipher.doFinal(inputBytes);
                outputStream.write(outputBytes);
            }


        } catch (NoSuchPaddingException | NoSuchAlgorithmException
                | InvalidKeyException | BadPaddingException
                | IllegalBlockSizeException | IOException ex) {
            throw new RuntimeException("Error encrypting/decrypting file", ex);
        }
    }
}
