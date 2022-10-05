package com.adioss.security.symmetric;

import java.security.Key;
import java.security.SecureRandom;
import org.junit.Assert;
import org.junit.Test;

public class SymmetricTest {
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    @Test
    public void shouldValidateEncryptWithKeyGeneratorWithoutException() {
        try {
            KeyGeneration.encryptWithKeyGenerator();
        } catch (Exception e) {
            Assert.fail("WHOOPS! Threw " + e.toString());
        }
    }

    @Test
    public void shouldValidateWrapUnwrapKeyWithoutException() {
        try {
            KeyWrapper.wrapUnwrapKey();
        } catch (Exception e) {
            Assert.fail("WHOOPS! Threw " + e.toString());
        }
    }

    @Test
    public void shouldValidateStreamWithoutException() {
        try {
            SimpleCipherTest.test();
        } catch (Exception e) {
            Assert.fail("WHOOPS! Threw " + e.toString());
        }
    }

    @Test

    public void shouldValidateSimpleCipherTestWithoutException() {
        try {
            SimpleCipherTest.test();
        } catch (Exception e) {
            Assert.fail("WHOOPS! Threw " + e.toString());
        }
    }

    @Test
    public void shouldDecryptWithPBE() throws Exception {
        // Given
        int iterationCount = 10;
        // 8 bytes long
        byte[] salt = new byte[8];
        SECURE_RANDOM.nextBytes(salt);
        String plaintext = "My plain text";
        String password = "my_pass";
        // When
        byte[] encryptedData = PBEEncryption.encrypt(plaintext, password, salt, iterationCount);
        // Then
        byte[] decryptedData = PBEEncryption.decrypt(encryptedData, password, salt, iterationCount);
        //System.out.println("Decrypted data: " + new String(decryptedData));
        Assert.assertEquals(plaintext, new String(decryptedData));
    }

    @Test
    public void shouldDecryptWithPBKDF2DerivedKey() throws Exception {
        // Given
        String plaintext = "My plain text";

        int iterationCount = 100000;
        byte[] salt = new byte[16];
        SECURE_RANDOM.nextBytes(salt);
        byte[] iv = new byte[12];
        SECURE_RANDOM.nextBytes(iv);
        String password = "my_pass";

        // When
        Key key = PBKDF2Derivation.deriveKey(password, salt, iterationCount, 128);
        // And
        byte[] encryptedData = PBKDF2Derivation.encrypt(key, iv, plaintext.getBytes());

        // Then
        byte[] decryptedData = PBKDF2Derivation.decrypt(key, iv, encryptedData);
        //System.out.println("Decrypted data: " + new String(decryptedData));
        Assert.assertEquals(plaintext, new String(decryptedData));
    }
}
