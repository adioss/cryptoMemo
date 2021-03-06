package com.adioss.security;

import java.io.*;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.io.Streams;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Charsets;
import sun.misc.BASE64Encoder;
import sun.security.provider.X509Factory;

public class Utils {
    private final static String DIGITS = "0123456789abcdef";

    public static byte[] generateSecureRandomBytes(int size) {
        SecureRandom secureRandom = new SecureRandom();
        byte[] bytes = new byte[size];
        secureRandom.nextBytes(bytes);
        return bytes;
    }

    /**
     * Return length many bytes of the passed in byte array as a hex string.
     *
     * @param data the bytes to be converted.
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

    public static IvParameterSpec createIvForAES(int messageNumber, SecureRandom random) {
        byte[] ivBytes = new byte[16];
        // initially randomize
        random.nextBytes(ivBytes);
        // set the message number bytes
        ivBytes[0] = (byte) (messageNumber >> 24);
        ivBytes[1] = (byte) (messageNumber >> 16);
        ivBytes[2] = (byte) (messageNumber >> 8);
        ivBytes[3] = (byte) (messageNumber);
        // set the counter bytes to 1
        for (int i = 0; i != 7; i++) {
            ivBytes[8 + i] = 0;
        }
        ivBytes[15] = 1;
        return new IvParameterSpec(ivBytes);
    }

    public static Key createKeyForAES(SecureRandom random) throws NoSuchProviderException, NoSuchAlgorithmException {
        return createKeyForAES(128, random);
    }

    public static Key createKeyForAES(int bitLength, SecureRandom random) throws NoSuchProviderException, NoSuchAlgorithmException {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(bitLength, random);
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

    public static SecureRandom createFixedRandom() {
        return new FixedRand();
    }

    public static X509Certificate openDerFile(InputStream inputStream) throws Exception {
        byte[] certData = Streams.readAll(inputStream);
        CertificateFactory jceFac = CertificateFactory.getInstance("X.509");
        return (X509Certificate) jceFac.generateCertificate(new ByteArrayInputStream(certData));
    }

    private static class FixedRand extends SecureRandom {
        private final MessageDigest sha;
        private byte[] state;

        FixedRand() {
            try {
                this.sha = MessageDigest.getInstance("SHA-384");
                this.state = sha.digest();
            } catch (Exception e) {
                throw new RuntimeException("can't find SHA-384!");
            }
        }

        public void nextBytes(byte[] bytes) {
            int off = 0;
            sha.update(state);
            while (off < bytes.length) {
                state = sha.digest();
                if (bytes.length - off > state.length) {
                    System.arraycopy(state, 0, bytes, off, state.length);
                } else {
                    System.arraycopy(state, 0, bytes, off, bytes.length - off);
                }
                off += state.length;
                sha.update(state);
            }
        }
    }

    /**
     * Print a {@link PKCS10CertificationRequest} cert request to the console
     */
    public static void printCertRequest(PKCS10CertificationRequest request) throws IOException {
        try (PEMWriter pemWrt = new PEMWriter(new OutputStreamWriter(System.out))) {
            pemWrt.writeObject(request);
        }
    }

    /**
     * Convert a ASN.1 DER certificate to a PEM format (
     */
    @VisibleForTesting
    static String convertToPemFormat(Certificate certificate) throws CertificateEncodingException, IOException {
        String rfc;
        try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
            new BASE64Encoder().encodeBuffer(certificate.getEncoded(), byteArrayOutputStream);
            rfc = new String(byteArrayOutputStream.toByteArray(), Charsets.UTF_8);
        }
        return X509Factory.BEGIN_CERT + System.lineSeparator() + rfc + System.lineSeparator() + X509Factory.END_CERT;
    }

    private Utils() {
    }
}
