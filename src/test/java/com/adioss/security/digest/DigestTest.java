package com.adioss.security.digest;

import org.junit.Assert;
import org.junit.Test;

public class DigestTest {
    @Test
    public void shouldValidateEncryptDecryptWithDigest() {
        try {
            Digest.encryptDecryptWithDigest();
        } catch (Exception e) {
            Assert.fail("WHOOPS! Threw " + e.toString());
            e.printStackTrace();
        }
    }

    @Test
    public void shouldValidateEncryptDecryptWithHMac() {
        try {
            Digest.encryptDecryptWithHMac();
        } catch (Exception e) {
            Assert.fail("WHOOPS! Threw " + e.toString());
            e.printStackTrace();
        }
    }
}