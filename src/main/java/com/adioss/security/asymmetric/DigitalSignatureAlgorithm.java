package com.adioss.security.asymmetric;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import com.adioss.security.Utils;

public class DigitalSignatureAlgorithm {
    /**
     * DSA: Digital Signature Algorithm
     */
    private static void createValidateSignatureWithDSA() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA", "BC");
        keyPairGenerator.initialize(512, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        Signature signature = Signature.getInstance("DSA", "BC");

        // generate a signature
        signature.initSign(keyPair.getPrivate(), Utils.createFixedRandom());
        byte[] message = new byte[]{(byte) 'a', (byte) 'b', (byte) 'c'};
        signature.update(message);
        byte[] signatureBytes = signature.sign();

        // verify a signature
        signature.initVerify(keyPair.getPublic());
        signature.update(message);
        if (signature.verify(signatureBytes)) {
            System.out.println("signature verification succeeded.");
        } else {
            System.out.println("signature verification failed.");
        }
    }

    /**
     * ECDSA: Ecliptic Curve Digital Signature Algorithm
     */
    private static void createValidateSignatureWithECDSA() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("prime192v1");
        keyPairGenerator.initialize(ecGenParameterSpec, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        Signature signature = Signature.getInstance("ECDSA", "BC");

        // generate a signature
        signature.initSign(keyPair.getPrivate(), Utils.createFixedRandom());
        byte[] message = new byte[]{(byte) 'a', (byte) 'b', (byte) 'c'};
        signature.update(message);
        byte[] signatureBytes = signature.sign();

        // verify a signature
        signature.initVerify(keyPair.getPublic());
        signature.update(message);
        if (signature.verify(signatureBytes)) {
            System.out.println("signature verification succeeded.");
        } else {
            System.out.println("signature verification failed.");
        }
    }

    /**
     * RSA-Based Signature Algorithms: PKCS #1 1.5 Signatures
     */
    private static void createValidateSignatureWithPKCS1() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("prime192v1");
        keyPairGenerator.initialize(ecGenParameterSpec, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        Signature signature = Signature.getInstance("ECDSA", "BC");

        // generate a signature
        signature.initSign(keyPair.getPrivate(), Utils.createFixedRandom());
        byte[] message = new byte[]{(byte) 'a', (byte) 'b', (byte) 'c'};
        signature.update(message);
        byte[] signatureBytes = signature.sign();

        // verify a signature
        signature.initVerify(keyPair.getPublic());
        signature.update(message);
        if (signature.verify(signatureBytes)) {
            System.out.println("signature verification succeeded.");
        } else {
            System.out.println("signature verification failed.");
        }
    }

    public static void main(String... args) throws Exception {
        createValidateSignatureWithDSA();
        createValidateSignatureWithECDSA();
        createValidateSignatureWithPKCS1();
    }
}
