package com.adioss.security.symmetric;

import org.junit.Assert;
import org.junit.Test;

public class StreamTest {
    @Test
    public void streamEncryptDecrypt() throws Exception {
        try {
            Stream.streamEncryptDecrypt();
        } catch (Exception e) {
            Assert.fail("WHOOPS! Threw " + e.toString());
        }
    }

}
