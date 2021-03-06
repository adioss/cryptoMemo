package com.adioss.security.digest;

import java.security.Key;
import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.adioss.security.Utils;
import com.google.common.annotations.VisibleForTesting;

import static java.lang.String.format;

class Digest {
    private static final Logger LOG = LoggerFactory.getLogger(Digest.class);
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Digest is computed over data:
     * Get from MessageDigest factory an instance
     * Append the input to cipher with update
     * Append the input to message digest with update
     * Complete cipher text with message digest(java.security.MessageDigest#digest()) with doFinal method
     */
    @VisibleForTesting
    static void encryptDecryptWithDigest() throws Exception {

        IvParameterSpec ivParameterSpec = Utils.createIvForAES(1, SECURE_RANDOM);
        Key key = Utils.createKeyForAES(SECURE_RANDOM);
        String input = "Validate with digested data.....";
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-384");
        LOG.debug("input : " + input);

        // encryption step
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
        byte[] cipherText = new byte[cipher.getOutputSize(input.length() + messageDigest.getDigestLength())];
        int cipherTextLength = cipher.update(Utils.toByteArray(input), 0, input.length(), cipherText, 0);
        messageDigest.update(Utils.toByteArray(input));
        cipherTextLength += cipher.doFinal(messageDigest.digest(), 0, messageDigest.getDigestLength(), cipherText, cipherTextLength);

        // here we change some data
        cipherText[9] ^= '0' ^ '9';

        // decryption step
        cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        byte[] plainText = cipher.doFinal(cipherText, 0, cipherTextLength);
        int messageLength = plainText.length - messageDigest.getDigestLength();
        messageDigest.update(plainText, 0, messageLength);
        byte[] messageHash = new byte[messageDigest.getDigestLength()];
        System.arraycopy(plainText, messageLength, messageHash, 0, messageHash.length);
        // message digest is false (see java.security.MessageDigest.isEqual)
        LOG.debug(format("plain : %s verified: %s%n", Utils.toString(plainText, messageLength), MessageDigest.isEqual(messageDigest.digest(), messageHash)));
    }

    /**
     * HMAC: Hash Message Authentication Code
     * HMAC is computed over data:
     * Get from Mac factory an instance and generate it (create key/init/update)
     * Append the input to cipher with update + doFinal
     * Complete cipher text with message digest(java.security.MessageDigest#digest()) with doFinal method
     */
    @VisibleForTesting
    static void encryptDecryptWithHMac() throws Exception {
        SecureRandom random = new SecureRandom();
        IvParameterSpec ivSpec = Utils.createIvForAES(1, random);
        Key key = Utils.createKeyForAES(128, random);
        String input = "Validate with digested data.....";
        LOG.debug("input : " + input);

        // mac generation
        Mac mac = Mac.getInstance("HmacSHA512");
        byte[] macKeyBytes = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        Key macKey = new SecretKeySpec(macKeyBytes, "HmacSHA512");
        mac.init(macKey);
        mac.update(Utils.toByteArray(input));
        LOG.debug("MacLength : " + mac.getMacLength());

        // encryption step
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] cipherText = new byte[cipher.getOutputSize(input.length() + mac.getMacLength())];
        int cypherTextLength = cipher.update(Utils.toByteArray(input), 0, input.length(), cipherText, 0);
        cypherTextLength += cipher.doFinal(mac.doFinal(), 0, mac.getMacLength(), cipherText, cypherTextLength);

        // decryption step
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] plainText = cipher.doFinal(cipherText, 0, cypherTextLength);
        int messageLength = plainText.length - mac.getMacLength();
        mac.init(macKey);
        mac.update(plainText, 0, messageLength);
        byte[] messageHash = new byte[mac.getMacLength()];
        System.arraycopy(plainText, messageLength, messageHash, 0, messageHash.length);
        LOG.debug("plain : " + Utils.toString(plainText, messageLength) + " verified: " + MessageDigest.isEqual(mac.doFinal(), messageHash));
    }

    private Digest() {
    }
}
