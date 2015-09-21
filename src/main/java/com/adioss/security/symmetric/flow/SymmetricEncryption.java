package com.adioss.security.symmetric.flow;

import com.adioss.security.symmetric.SymmetricEncryptTools;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import static com.adioss.security.symmetric.SymmetricEncryptTools.INPUT;

public class SymmetricEncryption {
    /**
     * Symmetric encrypt by flow with ARC4 cypher and Bouncy castle
     */
    private static void encryptWithSimpleSymmetricEncryption() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        byte[] keyBytes = new byte[]{
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

        SecretKeySpec key = new SecretKeySpec(keyBytes, "ARC4");
        Cipher cipher = Cipher.getInstance("ARC4", "BC");
        SymmetricEncryptTools.simpleEncryptDecrypt(INPUT, key, cipher);
    }

    public static void main(String[] args) throws Exception {
        encryptWithSimpleSymmetricEncryption();
    }
}
