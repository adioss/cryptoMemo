package com.adioss.security.asymmetric;

import org.junit.Assert;
import org.junit.Test;

public class DigitalSignatureAlgorithmTest {
    @Test
    public void shouldValidateCreateValidateSignatureWithDSA() {
        try {
            DigitalSignatureAlgorithm.createValidateSignatureWithDSA();
        } catch (Exception e) {
            Assert.fail("WHOOPS! Threw " + e.toString());
            e.printStackTrace();
        }
    }

    @Test
    public void shouldValidateCreateValidateSignatureWithPKCS1() {
        try {
            DigitalSignatureAlgorithm.createValidateSignatureWithPKCS1();
        } catch (Exception e) {
            Assert.fail("WHOOPS! Threw " + e.toString());
            e.printStackTrace();
        }
    }
}