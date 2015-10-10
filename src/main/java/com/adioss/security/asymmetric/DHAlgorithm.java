package com.adioss.security.asymmetric;

import com.adioss.security.Utils;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

/**
 * DH: Diffie Helman
 * Algo for key agreement: be agree on a key to exchange data
 */
public class DHAlgorithm {
    /**
     * {@link KeyPairGenerator} is initialized with two key grouped in a {@link DHParameterSpec} and generate two {@link KeyPair}
     * Generate two {@link KeyAgreement} and init with
     * - the private key from the other
     * - each other public key
     */
    private static void createKeysByKeyAgreementWithDH() throws Exception {
        BigInteger g512 = new BigInteger("153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7" +
                "749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b" +
                "410b7a0f12ca1cb9a428cc", 16);
        BigInteger p512 = new BigInteger("9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd387" +
                "44d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94b" +
                "f0573bf047a3aca98cdf3b", 16);

        DHParameterSpec dhParameterSpec = new DHParameterSpec(p512, g512);
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH", "BC");
        keyPairGenerator.initialize(dhParameterSpec, Utils.createFixedRandom());

        // set up
        KeyAgreement aKeyAgree = KeyAgreement.getInstance("DH", "BC");
        KeyPair aPair = keyPairGenerator.generateKeyPair();
        KeyAgreement bKeyAgree = KeyAgreement.getInstance("DH", "BC");
        KeyPair bPair = keyPairGenerator.generateKeyPair();

        // two party agreement
        aKeyAgree.init(aPair.getPrivate());
        bKeyAgree.init(bPair.getPrivate());

        aKeyAgree.doPhase(bPair.getPublic(), true);
        bKeyAgree.doPhase(aPair.getPublic(), true);

        // generate the key bytes
        MessageDigest hash = MessageDigest.getInstance("SHA1", "BC");
        byte[] aShared = hash.digest(aKeyAgree.generateSecret());
        byte[] bShared = hash.digest(bKeyAgree.generateSecret());

        System.out.println(Utils.toHex(aShared));
        System.out.println(Utils.toHex(bShared));
    }

    /**
     * Elliptic Curve Diffie Hellman
     */
    private static void createKeysByKeyAgreementWithECDH() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("ECDH", "BC");
        EllipticCurve curve = new EllipticCurve(new ECFieldFp(new BigInteger("fffffffffffffffffffffffffffffffeffffffffffffffff", 16)),
                new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16),
                new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16));

        ECParameterSpec ecSpec = new ECParameterSpec(curve, new ECPoint(new BigInteger("188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012", 16),
                new BigInteger("f8e6d46a003725879cefee1294db32298c06885ee186b7ee", 16)),
                new BigInteger("ffffffffffffffffffffffff99def836146bc9b1b4d22831", 16), 1);

        keyGen.initialize(ecSpec, Utils.createFixedRandom());

        // set up
        KeyAgreement aKeyAgree = KeyAgreement.getInstance("ECDH", "BC");
        KeyPair aPair = keyGen.generateKeyPair();
        KeyAgreement bKeyAgree = KeyAgreement.getInstance("ECDH", "BC");
        KeyPair bPair = keyGen.generateKeyPair();

        // two party agreement
        aKeyAgree.init(aPair.getPrivate());
        bKeyAgree.init(bPair.getPrivate());

        aKeyAgree.doPhase(bPair.getPublic(), true);
        bKeyAgree.doPhase(aPair.getPublic(), true);

        // generate the key bytes
        MessageDigest hash = MessageDigest.getInstance("SHA1", "BC");
        byte[] aShared = hash.digest(aKeyAgree.generateSecret());
        byte[] bShared = hash.digest(bKeyAgree.generateSecret());

        System.out.println(Utils.toHex(aShared));
        System.out.println(Utils.toHex(bShared));
    }

    public static void main(String... args) throws Exception {
        createKeysByKeyAgreementWithDH();
        createKeysByKeyAgreementWithECDH();
    }
}
