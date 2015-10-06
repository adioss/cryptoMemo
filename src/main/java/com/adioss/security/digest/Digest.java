package com.adioss.security.digest;

import com.adioss.security.Utils;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;

public class Digest {
    /**
     * Digest is computed over data:
     * Get from MessageDigest factory an instance
     * Append the input to cipher with update
     * Append the input to message digest with update
     * Complete cipher text with message digest(java.security.MessageDigest#digest()) with doFinal method
     */
    private static void simpleDigest() throws NoSuchProviderException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        SecureRandom random = new SecureRandom();
        IvParameterSpec ivParameterSpec = Utils.createCtrIvForAES(1, random);
        Key key = Utils.createKeyForAES(256, random);
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

    public static void main(String[] args) throws Exception {
        simpleDigest();
    }

}
