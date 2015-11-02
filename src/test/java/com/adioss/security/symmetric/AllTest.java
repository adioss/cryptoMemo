package com.adioss.security.symmetric;

import org.junit.Assert;
import org.junit.Test;

public class AllTest {
    @Test
    public void testDecrypt() {
        try {
            KeyGeneration.encryptWithKeyGenerator();
            KeyWrapper.wrapUnwrapKey();
            PBEEncryptor.simulateOneDESStep();
            SimpleCipherTest.test();
            Stream.streamEncryptDecrypt();
        } catch (Exception e) {
            Assert.fail("WHOOPS! Threw " + e.toString());
            e.printStackTrace();
        }

    }
}
