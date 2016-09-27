package com.adioss.security.symmetric.block;

import org.junit.Assert;
import org.junit.Test;

public class AESSymmetricEncryptionTest {
    @Test
    public void shouldEncryptDecryptECB() throws Exception {
        try {
            AESSymmetricEncryption.encryptDecryptECB();
        } catch (Exception e) {
            Assert.fail("WHOOPS! Threw " + e.toString());
            e.printStackTrace();
        }
    }

    @Test
    public void shouldEncryptDecryptCBC() throws Exception {
        try {
            AESSymmetricEncryption.encryptDecryptCBC();
        } catch (Exception e) {
            Assert.fail("WHOOPS! Threw " + e.toString());
            e.printStackTrace();
        }
    }

    @Test
    public void shouldEncryptDecryptGCM() throws Exception {
        try {
            AESSymmetricEncryption.encryptDecryptGCM();
        } catch (Exception e) {
            Assert.fail("WHOOPS! Threw " + e.toString());
            e.printStackTrace();
        }
    }

}