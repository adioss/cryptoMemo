package com.adioss.security.asymmetric;

import org.junit.Assert;
import org.junit.Test;
import com.adioss.security.AbstractBouncyCastleTest;

public class ElGamalAlgorithmTest extends AbstractBouncyCastleTest {
    @Test
    public void shouldEncryptDecryptWithElGamal() {
        try {
            ElGamalAlgorithm.encryptDecryptWithElGamal();
        } catch (Exception e) {
            Assert.fail("WHOOPS! Threw " + e.toString());
        }
    }

    @Test
    public void shouldEncryptDecryptWithElGamalWithParameters() {

        try {
            ElGamalAlgorithm.encryptDecryptWithElGamalWithParameters();
        } catch (Exception e) {
            Assert.fail("WHOOPS! Threw " + e.toString());
        }
    }
}
