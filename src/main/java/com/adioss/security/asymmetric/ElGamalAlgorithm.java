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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.adioss.security.Utils;

class ElGamalAlgorithm {
    private static final Logger LOG = LoggerFactory.getLogger(ElGamalAlgorithm.class);
    private static final String EL_GAMAL_CIPHER = "ElGamal/None/NoPadding";
    private static final String EL_GAMAL_ALGORITHM = "ElGamal";

    static void encryptDecryptWithElGamal() throws Exception {
        byte[] input = new byte[]{(byte) 0xbe, (byte) 0xef};
        Cipher cipher = Cipher.getInstance(EL_GAMAL_CIPHER);
        KeyPairGenerator generator = KeyPairGenerator.getInstance(EL_GAMAL_ALGORITHM);
        SecureRandom random = Utils.createFixedRandom();

        // create the keys
        generator.initialize(256, random);
        KeyPair pair = generator.generateKeyPair();
        Key publicKey = pair.getPublic();
        Key privateKey = pair.getPrivate();

        LOG.debug("input : " + Utils.toHex(input));

        // encryption step
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, random);
        byte[] cipherText = cipher.doFinal(input);
        LOG.debug("cipher: " + Utils.toHex(cipherText));

        // decryption step
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] plainText = cipher.doFinal(cipherText);
        LOG.debug("plain : " + Utils.toHex(plainText));
    }

    static void encryptDecryptWithElGamalWithParameters() throws Exception {
        byte[] input = new byte[]{(byte) 0xbe, (byte) 0xef};
        Cipher cipher = Cipher.getInstance(EL_GAMAL_CIPHER);
        SecureRandom random = Utils.createFixedRandom();

        // create the parameters
        AlgorithmParameterGenerator algorithmParameterGenerator = AlgorithmParameterGenerator.getInstance(EL_GAMAL_ALGORITHM);
        algorithmParameterGenerator.init(256, random);
        AlgorithmParameters params = algorithmParameterGenerator.generateParameters();
        AlgorithmParameterSpec dhSpec = params.getParameterSpec(DHParameterSpec.class);

        // create the keys
        KeyPairGenerator generator = KeyPairGenerator.getInstance(EL_GAMAL_ALGORITHM);
        generator.initialize(dhSpec, random);
        KeyPair pair = generator.generateKeyPair();
        Key publicKey = pair.getPublic();
        Key privateKey = pair.getPrivate();
        LOG.debug("input : " + Utils.toHex(input));

        // encryption step
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, random);
        byte[] cipherText = cipher.doFinal(input);
        LOG.debug("cipher: " + Utils.toHex(cipherText));

        // decryption step
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] plainText = cipher.doFinal(cipherText);
        LOG.debug("plain : " + Utils.toHex(plainText));
    }

    private ElGamalAlgorithm() {
    }
}
