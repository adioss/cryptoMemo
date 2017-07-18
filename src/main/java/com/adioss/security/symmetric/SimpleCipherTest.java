package com.adioss.security.symmetric;

import javax.crypto.*;
import javax.crypto.spec.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.annotations.VisibleForTesting;

class SimpleCipherTest {
    private static final Logger LOG = LoggerFactory.getLogger(SimpleCipherTest.class);

    /**
     * remark: without jce unlimited, key192 will not work
     * => http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html
     */
    @VisibleForTesting
    public static void test() throws Exception {
        byte[] data = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};

        // create a 64 bit(8 bytes) secret key from raw bytes
        SecretKey key64 = new SecretKeySpec(new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}, "Blowfish");
        // create a cipher and attempt to encrypt the data block with our key
        Cipher cipher = Cipher.getInstance("Blowfish/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key64);
        cipher.doFinal(data);
        LOG.debug("64 bit test: passed");

        // create a 128 bit(16 bytes) secret key from raw bytes
        SecretKey key128 = new SecretKeySpec(new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
                                             "Blowfish");
        // now try encrypting with the larger key
        cipher.init(Cipher.ENCRYPT_MODE, key128);
        cipher.doFinal(data);
        LOG.debug("128 bit test: passed");

        LOG.debug("Tests completed");
    }

    private SimpleCipherTest() {
    }
}
