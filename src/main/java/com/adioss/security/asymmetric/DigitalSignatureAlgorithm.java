package com.adioss.security.asymmetric;

import com.adioss.security.Utils;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Signature;

import static com.adioss.security.SignatureSUNConstant.SHA1withRSA;

public class DigitalSignatureAlgorithm {
    /**
     * DSA: Digital Signature Algorithm
     */
    static void createValidateSignatureWithDSA() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        keyPairGenerator.initialize(512, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        Signature signature = Signature.getInstance("DSA");

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
    static void createValidateSignatureWithPKCS1() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(512, new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();
        Signature signature = Signature.getInstance(SHA1withRSA);

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
        createValidateSignatureWithPKCS1();
    }
}
