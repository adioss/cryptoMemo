package com.adioss.security.symmetric.block;

import javax.crypto.*;
import javax.crypto.spec.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.adioss.security.Utils;
import com.google.common.annotations.VisibleForTesting;

import static com.adioss.security.symmetric.SymmetricEncryptConstant.INPUT;
import static com.adioss.security.symmetric.SymmetricEncryptTools.*;

class ModeForSymmetricEncryption {
    private static final Logger LOG = LoggerFactory.getLogger(ModeForSymmetricEncryption.class);

    /**
     * Symmetric encrypt by block with ECB mode: PKCS7 Padding using DES cipher
     * Problem: show that we can discovering patterns
     */
    @VisibleForTesting
    static void encryptWithECB() throws Exception {
        LOG.debug("encryptWithECB");
        byte[] keyBytes = new byte[]{0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef};

        SecretKeySpec key = new SecretKeySpec(keyBytes, "DES");
        // here ECB
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

        simpleEncryptDecrypt(INPUT, key, cipher);
        // print cipher: 3260266c2cf202e28325790654a444d93260266c2cf202e2086f9a1d74c94d4e bytes: 32
        // we can see that 3260266c2cf202e2 is printed two times: same encryption pattern discovery
    }

    /**
     * Symmetric encrypt by block with CBC mode: PKCS7 Padding using DES cipher and IV
     */
    @VisibleForTesting
    static void encryptWithCBC() throws Exception {
        LOG.debug("encryptWithCBC");
        byte[] keyBytes = new byte[]{0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef};
        byte[] ivBytes = Utils.generateSecureRandomBytes(8);

        SecretKeySpec key = new SecretKeySpec(keyBytes, "DES");
        // used to init cipher
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");

        encryptDecryptWithIV(INPUT, key, ivSpec, cipher);
    }

    /**
     * Symmetric encrypt by block with CBC mode: PKCS7 Padding using DES cipher and secure random IV
     */
    @VisibleForTesting
    static void encryptWithCBCWithSecureRandomIV() throws Exception {
        LOG.debug("encryptWithCBCWithSecureRandomIV");
        byte[] keyBytes = new byte[]{0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef};
        byte[] ivBytes = Utils.generateSecureRandomBytes(8);

        SecretKeySpec key = new SecretKeySpec(keyBytes, "DES");
        // used to init cipher
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        // secure random can be done by calling cipher method too
        // see => IvParameterSpec ivSpec = new IvParameterSpec(cipher.getIV());
        encryptDecryptWithIV(INPUT, key, ivSpec, cipher);
    }

    /**
     * Symmetric encrypt by block with CTS mode: no padding using DES cipher and IV
     */
    @VisibleForTesting
    static void encryptWithCTS() throws Exception {
        LOG.debug("encryptWithCTS");
        byte[] keyBytes = new byte[]{0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef};
        byte[] ivBytes = Utils.generateSecureRandomBytes(8);

        SecretKeySpec key = new SecretKeySpec(keyBytes, "DES");
        // used to init cipher
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        Cipher cipher = Cipher.getInstance("DES/CTS/NoPadding");

        encryptDecryptWithIV(INPUT, key, ivSpec, cipher);
    }

    /**
     * Symmetric encrypt by block with CTR mode: no padding using DES cipher and IV
     */
    @VisibleForTesting
    static void encryptWithCTR() throws Exception {
        LOG.debug("encryptWithCBC");
        byte[] keyBytes = new byte[]{0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef};
        byte[] ivBytes = new byte[]{0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};

        SecretKeySpec key = new SecretKeySpec(keyBytes, "DES");
        // used to init cipher
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        Cipher cipher = Cipher.getInstance("DES/CTR/NoPadding");

        encryptDecryptWithIV(INPUT, key, ivSpec, cipher);
    }

    private ModeForSymmetricEncryption() {
    }
}
