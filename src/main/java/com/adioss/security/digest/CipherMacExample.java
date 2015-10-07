package com.adioss.security.digest;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import javax.crypto.*;
import javax.crypto.spec.*;
import com.adioss.security.Utils;

public class CipherMacExample {
    private CipherMacExample() {
    }

    private static void encryptDecryptWithMac()
            throws NoSuchProviderException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException,
                   ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        String input = "Transfer 0000100 to AC 1234-5678";
        System.out.println("input : " + input);

        SecureRandom random = new SecureRandom();
        IvParameterSpec ivSpec = Utils.createCtrIvForAES(1, random);
        Key key = Utils.createKeyForAES(256, random);
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
        Mac mac = Mac.getInstance("DES", "BC");
        byte[] macKeyBytes = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        Key macKey = new SecretKeySpec(macKeyBytes, "DES");

        // encryption step
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] cipherText = new byte[cipher.getOutputSize(input.length() + mac.getMacLength())];
        int cypherTextLength = cipher.update(Utils.toByteArray(input), 0, input.length(), cipherText, 0);
        mac.init(macKey);
        mac.update(Utils.toByteArray(input));
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
        encryptDecryptWithMac();
    }
}
