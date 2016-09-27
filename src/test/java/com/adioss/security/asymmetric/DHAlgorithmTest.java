package com.adioss.security.asymmetric;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

public class DHAlgorithmTest {
    @Test
    public void shouldValidateCreateKeysByKeyAgreementWithDH() {
        try {
            DHAlgorithm.createKeysByKeyAgreementWithDH();
        } catch (Exception e) {
            Assert.fail("WHOOPS! Threw " + e.toString());
            e.printStackTrace();
        }
    }

    @Ignore
    @Test
    public void shouldValidateCreateKeysByKeyAgreementWithECDH() {
        try {
            DHAlgorithm.createKeysByKeyAgreementWithECDH();
        } catch (Exception e) {
            Assert.fail("WHOOPS! Threw " + e.toString());
            e.printStackTrace();
        }
    }
}