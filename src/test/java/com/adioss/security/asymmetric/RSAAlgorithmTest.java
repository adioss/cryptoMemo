package com.adioss.security.asymmetric;

import org.junit.Test;

public class RSAAlgorithmTest {

    @Test
    public void shouldEncryptDecryptWithPublicPrivateRSAKeysGenerated() throws Exception {
        RSAAlgorithm.encryptDecryptWithPublicPrivateRSAKeysGenerated();
    }

    @Test
    public void shouldEncryptDecryptWithPublicPrivateRSAKeysWithExponentManuallyGenerated() throws Exception {
        RSAAlgorithm.encryptDecryptWithPublicPrivateRSAKeysWithExponentManuallyGenerated();
    }

    @Test
    public void shouldEncryptDecryptWithPublicPrivatePKCS1Padding() throws Exception {
        RSAAlgorithm.encryptDecryptWithPublicPrivatePKCS1Padding();
    }

    @Test
    public void shouldEncryptDecryptWithPublicPrivateOAEPPadding() throws Exception {
        RSAAlgorithm.encryptDecryptWithPublicPrivateOAEPPadding();
    }

    @Test
    public void shouldEncryptDecryptWrappedSymmetricWithAsymmetricKey() throws Exception {
        RSAAlgorithm.encryptDecryptWrappedSymmetricWithAsymmetricKey();
    }
}