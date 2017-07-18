package com.adioss.security.symmetric.flow;

import org.junit.Assert;
import org.junit.Test;

public class SymmetricFlowEncryptionTest {
    @Test
    public void shouldValidateSymmetricEncryptionWithoutException() {
        try {
            SymmetricFlowEncryption.encryptWithSimpleSymmetricEncryption();
        } catch (Exception e) {
            Assert.fail("WHOOPS! Threw " + e.toString());
        }
    }
}
