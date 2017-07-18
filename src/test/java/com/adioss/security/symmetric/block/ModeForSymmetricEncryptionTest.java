package com.adioss.security.symmetric.block;

import org.junit.Assert;
import org.junit.Test;

public class ModeForSymmetricEncryptionTest {
    @Test
    public void shouldValidateEncryptWithECBWithoutException() {
        try {
            ModeForSymmetricEncryption.encryptWithECB();
        } catch (Exception e) {
            Assert.fail("WHOOPS! Threw " + e.toString());
        }
    }

    @Test
    public void shouldValidateEncryptWithCBCWithoutException() {
        try {
            ModeForSymmetricEncryption.encryptWithCBC();
        } catch (Exception e) {
            Assert.fail("WHOOPS! Threw " + e.toString());
        }
    }

    @Test
    public void shouldValidateEncryptWithCBCWithSecureRandomIVWithoutException() {
        try {
            ModeForSymmetricEncryption.encryptWithCBCWithSecureRandomIV();
        } catch (Exception e) {
            Assert.fail("WHOOPS! Threw " + e.toString());
        }
    }

    @Test
    public void shouldValidateEncryptWithCTSWithoutException() {
        try {
            ModeForSymmetricEncryption.encryptWithCTS();
        } catch (Exception e) {
            Assert.fail("WHOOPS! Threw " + e.toString());
        }
    }

    @Test
    public void shouldValidateEncryptWithCTRWithoutException() {
        try {
            ModeForSymmetricEncryption.encryptWithCTR();
        } catch (Exception e) {
            Assert.fail("WHOOPS! Threw " + e.toString());
        }
    }

}
