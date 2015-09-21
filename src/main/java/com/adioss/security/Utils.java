package com.adioss.security;

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
}
