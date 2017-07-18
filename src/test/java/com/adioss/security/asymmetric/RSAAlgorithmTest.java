package com.adioss.security.asymmetric;

import org.junit.Assert;
import org.junit.Test;

public class RSAAlgorithmTest {

    @Test
    public void shouldEncryptDecryptWithPublicPrivateRSAKeysGenerated() {
        try {
            RSAAlgorithm.encryptDecryptWithPublicPrivateRSAKeysGenerated();
        } catch (Exception e) {
            Assert.fail("WHOOPS! Threw " + e.toString());
        }
    }

    @Test
    public void encryptDecryptWithPublicPrivateRSAKeysWithExponentManuallyGenerated() {
        try {
            RSAAlgorithm.encryptDecryptWithPublicPrivateRSAKeysWithExponentManuallyGenerated();
        } catch (Exception e) {
            Assert.fail("WHOOPS! Threw " + e.toString());
        }
    }

    @Test
    public void shouldEncryptDecryptWithPublicPrivatePKCS1Padding() {
        try {
            RSAAlgorithm.encryptDecryptWithPublicPrivatePKCS1Padding();
        } catch (Exception e) {
            Assert.fail("WHOOPS! Threw " + e.toString());
        }
    }

    @Test
    public void shouldEncryptDecryptWithPublicPrivateOAEPPadding() {
        try {
            RSAAlgorithm.encryptDecryptWithPublicPrivateOAEPPadding();
        } catch (Exception e) {
            Assert.fail("WHOOPS! Threw " + e.toString());
        }
    }

    @Test
    public void shouldEncryptDecryptWrappedSymmetricWithAsymmetricKey() {
        try {
            RSAAlgorithm.encryptDecryptWrappedSymmetricWithAsymmetricKey();
        } catch (Exception e) {
            Assert.fail("WHOOPS! Threw " + e.toString());
        }
    }
}
