package com.adioss.security.symmetric.flow;

import javax.crypto.*;
import javax.crypto.spec.*;
import com.adioss.security.symmetric.SymmetricEncryptTools;

import static com.adioss.security.symmetric.SymmetricEncryptConstant.INPUT;

class SymmetricFlowEncryption {
    /**
     * Symmetric encrypt by flow with ARC4 cypher
     */
    static void encryptWithSimpleSymmetricEncryption() throws Exception {
        byte[] keyBytes = new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

        SecretKeySpec key = new SecretKeySpec(keyBytes, "ARCFOUR");
        Cipher cipher = Cipher.getInstance("ARCFOUR");
        SymmetricEncryptTools.simpleEncryptDecrypt(INPUT, key, cipher);
    }

    private SymmetricFlowEncryption() {
    }
}
