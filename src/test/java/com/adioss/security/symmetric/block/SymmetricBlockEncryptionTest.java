package com.adioss.security.symmetric.block;

import org.junit.Assert;
import org.junit.Test;

public class SymmetricBlockEncryptionTest {
    @Test
    public void shouldValidateSymmetricEncryptionWithoutException() {
        try {
            SymmetricBlockEncryption.encryptWithSimpleSymmetricEncryption();
        } catch (Exception e) {
            Assert.fail("WHOOPS! Threw " + e.toString());
        }
    }

}
