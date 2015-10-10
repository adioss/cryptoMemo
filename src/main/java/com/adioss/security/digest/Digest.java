package com.adioss.security.digest;

import com.adioss.security.Utils;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

public class Digest {
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Digest is computed over data:
     * Get from MessageDigest factory an instance
     * Append the input to cipher with update
     * Append the input to message digest with update
     * Complete cipher text with message digest(java.security.MessageDigest#digest()) with doFinal method
     */
    private static void encryptDecryptWithDigest()
            throws NoSuchProviderException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException,
            ShortBufferException, IllegalBlockSizeException, BadPaddingException {

        IvParameterSpec ivParameterSpec = Utils.createIvForAES(1, SECURE_RANDOM);
        Key key = Utils.createKeyForAES(SECURE_RANDOM);
        String input = "Validate with digested data.....";
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-1", "BC");
        System.out.println("input : " + input);

        // encryption step
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
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
        System.out.printf("plain : %s verified: %s%n", Utils.toString(plainText, messageLength), MessageDigest.isEqual(messageDigest.digest(), messageHash));
    }

    /**
     * HMAC: Hash Message Authentication Code
     * HMAC is computed over data:
     * Get from Mac factory an instance and generate it (create key/init/update)
     * Append the input to cipher with update + doFinal
     * Complete cipher text with message digest(java.security.MessageDigest#digest()) with doFinal method
     */
    private static void encryptDecryptWithHMac()
            throws NoSuchProviderException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException,
            ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        SecureRandom random = new SecureRandom();
        IvParameterSpec ivSpec = Utils.createIvForAES(1, random);
        Key key = Utils.createKeyForAES(256, random);
        String input = "Validate with digested data.....";
        System.out.println("input : " + input);

        // mac generation
        Mac mac = Mac.getInstance("DES", "BC");
        byte[] macKeyBytes = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        Key macKey = new SecretKeySpec(macKeyBytes, "DES");
        mac.init(macKey);
        mac.update(Utils.toByteArray(input));
        System.out.println("MacLength : " + mac.getMacLength());

        // encryption step
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
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
        System.out.println("plain : " + Utils.toString(plainText, messageLength) + " verified: " + MessageDigest.isEqual(mac.doFinal(), messageHash));
    }

    public static void main(String[] args) throws Exception {
        encryptDecryptWithDigest();
        encryptDecryptWithHMac();
    }
}
