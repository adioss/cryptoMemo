package com.adioss.security.asymmetric;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

import static org.junit.Assert.assertTrue;

public class DHAlgorithmTest {
    @Test
    public void shouldValidateCreateKeysByKeyAgreementWithDH() {
        try {
            assertTrue(DHAlgorithm.createKeysByKeyAgreementWithDH());
        } catch (Exception e) {
            Assert.fail("WHOOPS! Threw " + e.toString());
        }
    }

    @Ignore
    @Test
    public void shouldValidateCreateKeysByKeyAgreementWithECDH() {
        try {
            assertTrue(DHAlgorithm.createKeysByKeyAgreementWithECDH());
        } catch (Exception e) {
            Assert.fail("WHOOPS! Threw " + e.toString());
        }
    }
}
