package com.adioss.security.asymmetric;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.adioss.security.Utils;
import com.google.common.annotations.VisibleForTesting;

/**
 * DH: Diffie Helman
 * Algo for key agreement: be agree on a key to exchange data
 */
class DHAlgorithm {
    private static final Logger LOG = LoggerFactory.getLogger(DHAlgorithm.class);
    private static final String DH = "DH";
    private static final String ECDH = "ECDH";

    /**
     * {@link KeyPairGenerator} is initialized with two key grouped in a {@link DHParameterSpec} and generate two {@link KeyPair}
     * Generate two {@link KeyAgreement} and init with
     * - the private key
     * - each other public key
     */
    @VisibleForTesting
    static boolean createKeysByKeyAgreementWithDH() throws Exception {
        BigInteger g512 = new BigInteger(
                "153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc", 16);
        BigInteger p512 = new BigInteger(
                "9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b", 16);

        DHParameterSpec dhParameterSpec = new DHParameterSpec(p512, g512);
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(DH);
        keyPairGenerator.initialize(dhParameterSpec, Utils.createFixedRandom());

        // set up
        KeyAgreement keyAgreement1 = KeyAgreement.getInstance(DH);
        KeyPair keyPair1 = keyPairGenerator.generateKeyPair();
        KeyAgreement keyAgreement2 = KeyAgreement.getInstance(DH);
        KeyPair keyPair2 = keyPairGenerator.generateKeyPair();

        // two party agreement
        keyAgreement1.init(keyPair1.getPrivate());
        keyAgreement2.init(keyPair2.getPrivate());

        keyAgreement1.doPhase(keyPair2.getPublic(), true);
        keyAgreement2.doPhase(keyPair1.getPublic(), true);

        // generate the key bytes
        MessageDigest hash = MessageDigest.getInstance("SHA-384");
        byte[] digestSecretAgreement1 = hash.digest(keyAgreement1.generateSecret());
        byte[] digestSecretAgreement2 = hash.digest(keyAgreement2.generateSecret());

        LOG.debug("digestSecretAgreement1: " + Utils.toHex(digestSecretAgreement1) + " digestSecretAgreement2: " + Utils.toHex(digestSecretAgreement2));
        return Arrays.equals(digestSecretAgreement1, digestSecretAgreement2);
    }

    /**
     * Elliptic Curve Diffie Hellman
     */
    @VisibleForTesting
    static boolean createKeysByKeyAgreementWithECDH() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ECDH);
        EllipticCurve curve = new EllipticCurve(new ECFieldFp(new BigInteger("fffffffffffffffffffffffffffffffeffffffffffffffff", 16)),
                                                new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16),
                                                new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16));
        ECPoint generator = new ECPoint(new BigInteger("188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012", 16),
                                        new BigInteger("f8e6d46a003725879cefee1294db32298c06885ee186b7ee", 16));
        BigInteger order = new BigInteger("ffffffffffffffffffffffff99def836146bc9b1b4d22831", 16);
        int cofactor = 1;

        ECParameterSpec ecParameterSpec = new ECParameterSpec(curve, generator, order, cofactor);

        keyGen.initialize(ecParameterSpec, Utils.createFixedRandom());

        // set up
        KeyAgreement keyAgreement1 = KeyAgreement.getInstance(ECDH);
        KeyPair keyPair1 = keyGen.generateKeyPair();
        KeyAgreement keyAgreement2 = KeyAgreement.getInstance(ECDH);
        KeyPair keyPair2 = keyGen.generateKeyPair();

        // two party agreement
        keyAgreement1.init(keyPair1.getPrivate());
        keyAgreement2.init(keyPair2.getPrivate());

        keyAgreement1.doPhase(keyPair2.getPublic(), true);
        keyAgreement2.doPhase(keyPair1.getPublic(), true);

        // generate the key bytes
        MessageDigest hash = MessageDigest.getInstance("SHA-384");
        byte[] digestSecretAgreement1 = hash.digest(keyAgreement1.generateSecret());
        byte[] digestSecretAgreement2 = hash.digest(keyAgreement2.generateSecret());

        LOG.debug("digestSecretAgreement1: " + Utils.toHex(digestSecretAgreement1) + " digestSecretAgreement2: " + Utils.toHex(digestSecretAgreement2));
        return Arrays.equals(digestSecretAgreement1, digestSecretAgreement2);
    }

    private DHAlgorithm() {
    }
}
