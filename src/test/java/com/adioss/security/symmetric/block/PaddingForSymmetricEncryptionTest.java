package com.adioss.security.symmetric.block;

import org.junit.Assert;
import org.junit.Test;

public class PaddingForSymmetricEncryptionTest {
    @Test
    public void shouldValidateEncryptWithPaddingWithoutException() {
        try {
            PaddingForSymmetricEncryption.encryptWithPadding();
        } catch (Exception e) {
            Assert.fail("WHOOPS! Threw " + e.toString());
            e.printStackTrace();
        }
    }
}