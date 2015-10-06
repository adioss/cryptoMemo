package com.adioss.security;

import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

public class Utils {
    private final static String DIGITS = "0123456789abcdef";

    /**
     * Return length many bytes of the passed in byte array as a hex string.
     *
     * @param data   the bytes to be converted.
     * @param length the number of bytes in the data block to be converted.
     * @return a hex representation of length bytes of data.
     */
    public static String toHex(byte[] data, int length) {
        StringBuilder buf = new StringBuilder();

        for (int i = 0; i != length; i++) {
            int v = data[i] & 0xff;

            buf.append(DIGITS.charAt(v >> 4));
            buf.append(DIGITS.charAt(v & 0xf));
        }

        return buf.toString();
    }

    /**
     * Return the passed in byte array as a hex string.
     *
     * @param data the bytes to be converted.
     * @return a hex representation of data.
     */
    public static String toHex(byte[] data) {
        return toHex(data, data.length);
    }

    public static IvParameterSpec createCtrIvForAES(int messageNumber, SecureRandom random) {
        byte[] ivBytes = new byte[16];
        // initially randomize
        random.nextBytes(ivBytes);
        // set the message number bytes
        ivBytes[0] = (byte) (messageNumber >> 24);
        ivBytes[1] = (byte) (messageNumber >> 16);
        ivBytes[2] = (byte) (messageNumber >> 8);
        ivBytes[3] = (byte) (messageNumber >> 0);
        // set the counter bytes to 1
        for (int i = 0; i != 7; i++) {
            ivBytes[8 + i] = 0;
        }
        ivBytes[15] = 1;
        return new IvParameterSpec(ivBytes);
    }

    public static Key createKeyForAES(int i, SecureRandom random) throws NoSuchProviderException, NoSuchAlgorithmException {
        KeyGenerator generator = KeyGenerator.getInstance("AES", "BC");
        generator.init(256, random);
        return generator.generateKey();
    }

    public static byte[] toByteArray(String input) {
        byte[] bytes = new byte[input.length()];
        char[] chars = input.toCharArray();
        for (int i = 0; i != chars.length; i++) {
            bytes[i] = (byte) chars[i];
        }
        return bytes;
    }

    public static String toString(byte[] bytes, int length) {
        char[] chars = new char[length];
        for (int i = 0; i != chars.length; i++) {
            chars[i] = (char) (bytes[i] & 0xff);
        }
        return new String(chars);
    }
}
