package com.adioss.security.symmetric;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class SimpleCipherTest {
    public static void test() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] data = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};

        // create a 64 bit(8 bytes) secret key from raw bytes
        SecretKey key64 = new SecretKeySpec(
                new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
                "Blowfish");
        // create a cipher and attempt to encrypt the data block with our key
        Cipher cipher = Cipher.getInstance("Blowfish/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key64);
        cipher.doFinal(data);
        System.out.println("64 bit test: passed");


        // create a 192 bit(24 bytes) secret key from raw bytes
        SecretKey key192 = new SecretKeySpec(
                new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17},
                "Blowfish");
        // now try encrypting with the larger key
        cipher.init(Cipher.ENCRYPT_MODE, key192);
        cipher.doFinal(data);
        System.out.println("192 bit test: passed");


        System.out.println("Tests completed");
    }

    /**
     * remark: without jce unlimited, key192 will not work
     * => http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html
     */
    public static void main(String[] args) throws Exception {
        test();
    }

}
