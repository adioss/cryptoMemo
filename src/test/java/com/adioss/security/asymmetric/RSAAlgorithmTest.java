package com.adioss.security.asymmetric;

import org.junit.Test;

public class RSAAlgorithmTest {

    @Test
    public void shouldEncryptDecryptWithPublicPrivateRSAKeys() throws Exception {
        RSAAlgorithm.encryptDecryptWithPublicPrivateRSAKeys();
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
    public void shouldEncryptDecryptAsymmetricKey() throws Exception {
        RSAAlgorithm.encryptDecryptAsymmetricKey();
    }
}