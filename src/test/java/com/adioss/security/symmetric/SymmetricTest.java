package com.adioss.security.symmetric;

import org.junit.Assert;
import org.junit.Test;

public class SymmetricTest {


    @Test
    public void shouldValidateEncryptWithKeyGeneratorWithoutException() {
        try {
            KeyGeneration.encryptWithKeyGenerator();
        } catch (Exception e) {
            Assert.fail("WHOOPS! Threw " + e.toString());
            e.printStackTrace();
        }
    }

    @Test
    public void shouldValidateWrapUnwrapKeyWithoutException() {
        try {
            KeyWrapper.wrapUnwrapKey();
        } catch (Exception e) {
            Assert.fail("WHOOPS! Threw " + e.toString());
            e.printStackTrace();
        }
    }

    //    @Test
    public void shouldValidatePBEEncryptorSimulateOneDESStepWithoutException() {
        try {
            PBEEncryptor.simulateOneDESStep();
        } catch (Exception e) {
            Assert.fail("WHOOPS! Threw " + e.toString());
            e.printStackTrace();
        }
    }

    @Test
    public void shouldValidateStreamWithoutException() {
        try {
            SimpleCipherTest.test();
        } catch (Exception e) {
            Assert.fail("WHOOPS! Threw " + e.toString());
            e.printStackTrace();
        }
    }

    @Test

    public void shouldValidateSimpleCipherTestWithoutException() {
        try {
            SimpleCipherTest.test();
        } catch (Exception e) {
            Assert.fail("WHOOPS! Threw " + e.toString());
            e.printStackTrace();
        }
    }


    @Test
    public void shouldDecryptWithPBE() throws Exception {
        // Given
        int iterationCount = 10;
        // 8 bytes long
        byte[] salt = new byte[]{0x7d, 0x60, 0x43, 0x5f, 0x7d, 0x60, 0x43, 0x5f};
        String plaintext = "My plain text";
        String password = "my_pass";
        // When
        byte[] encryptedData = PBEEncryptor.encrypt(plaintext, password, salt, iterationCount);
        // Then
        byte[] decryptedData = PBEEncryptor.decrypt(encryptedData, password, salt, iterationCount);
        System.out.println("Decrypted data: " + new String(decryptedData));
        Assert.assertEquals(plaintext, new String(decryptedData));
    }
}
