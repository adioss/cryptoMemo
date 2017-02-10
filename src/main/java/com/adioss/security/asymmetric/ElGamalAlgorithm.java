package com.adioss.security.asymmetric;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.*;
import javax.crypto.spec.*;
import com.adioss.security.Utils;

public class ElGamalAlgorithm {
    private static void encryptDecryptWithElGamal() throws Exception {
        byte[] input = new byte[]{(byte) 0xbe, (byte) 0xef};
        Cipher cipher = Cipher.getInstance("ElGamal/None/NoPadding");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("ElGamal");
        SecureRandom random = Utils.createFixedRandom();

        // create the keys
        generator.initialize(256, random);
        KeyPair pair = generator.generateKeyPair();
        Key publicKey = pair.getPublic();
        Key privateKey = pair.getPrivate();

        System.out.println("input : " + Utils.toHex(input));

        // encryption step
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, random);
        byte[] cipherText = cipher.doFinal(input);
        System.out.println("cipher: " + Utils.toHex(cipherText));

        // decryption step
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] plainText = cipher.doFinal(cipherText);
        System.out.println("plain : " + Utils.toHex(plainText));
    }

    private static void encryptDecryptWithElGamalWithParameters() throws Exception {
        byte[] input = new byte[]{(byte) 0xbe, (byte) 0xef};
        Cipher cipher = Cipher.getInstance("ElGamal/None/NoPadding");
        SecureRandom random = Utils.createFixedRandom();

        // create the parameters
        AlgorithmParameterGenerator algorithmParameterGenerator = AlgorithmParameterGenerator.getInstance("ElGamal");
        algorithmParameterGenerator.init(256, random);
        AlgorithmParameters params = algorithmParameterGenerator.generateParameters();
        AlgorithmParameterSpec dhSpec = params.getParameterSpec(DHParameterSpec.class);

        // create the keys
        KeyPairGenerator generator = KeyPairGenerator.getInstance("ElGamal");
        generator.initialize(dhSpec, random);
        KeyPair pair = generator.generateKeyPair();
        Key publicKey = pair.getPublic();
        Key privateKey = pair.getPrivate();
        System.out.println("input : " + Utils.toHex(input));

        // encryption step
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, random);
        byte[] cipherText = cipher.doFinal(input);
        System.out.println("cipher: " + Utils.toHex(cipherText));

        // decryption step
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] plainText = cipher.doFinal(cipherText);
        System.out.println("plain : " + Utils.toHex(plainText));
    }

    public static void main(String... args) throws Exception {
        encryptDecryptWithElGamal();
        encryptDecryptWithElGamalWithParameters();
    }

    private ElGamalAlgorithm() {
    }
}
