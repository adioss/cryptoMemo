package com.adioss.security.symmetric.block;

import javax.crypto.*;
import javax.crypto.spec.*;
import com.adioss.security.Utils;

public class SymmetricBlockEncryption {
    static void encryptWithSimpleSymmetricEncryption() throws Exception {
        byte[] input = new byte[]{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb, (byte) 0xcc, (byte) 0xdd,
                (byte) 0xee, (byte) 0xff};
        byte[] keyBytes = new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        System.out.println("input text : " + Utils.toHex(input));

        // encryption pass
        byte[] cipherText = new byte[input.length];
        cipher.init(Cipher.ENCRYPT_MODE, key);
        int cipherTextLength = cipher.update(input, 0, input.length, cipherText, 0);
        cipherTextLength += cipher.doFinal(cipherText, cipherTextLength);
        System.out.println("cipher text: " + Utils.toHex(cipherText) + " bytes: " + cipherTextLength);

        // decryption pass
        byte[] plainText = new byte[cipherTextLength];
        cipher.init(Cipher.DECRYPT_MODE, key);
        int plainTextLength = cipher.update(cipherText, 0, cipherTextLength, plainText, 0);
        plainTextLength += cipher.doFinal(plainText, plainTextLength);
        System.out.println("plain text : " + Utils.toHex(plainText) + " bytes: " + plainTextLength);
    }

    public static void main(String[] args) throws Exception {
        encryptWithSimpleSymmetricEncryption();
    }
}
