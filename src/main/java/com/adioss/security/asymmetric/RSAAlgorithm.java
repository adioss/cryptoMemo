package com.adioss.security.asymmetric;

import java.io.*;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import javax.crypto.*;
import javax.crypto.spec.*;
import com.adioss.security.Utils;

/**
 * RSA: Rivest, Shamir, Adleman
 */
public class RSAAlgorithm {

    private static final byte[] INPUT = new byte[]{0x00, (byte) 0xbe, (byte) 0xef};

    /**
     * RSA public/private key generated
     */
    static void encryptDecryptWithPublicPrivateRSAKeysGenerated() throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");

        // create the keys
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.genKeyPair();
        PublicKey publicKey = kp.getPublic();
        PrivateKey privateKey = kp.getPrivate();

        System.out.println("input : " + Utils.toHex(INPUT));

        // encryption step
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] cipherText = cipher.doFinal(INPUT);
        System.out.println("cipher: " + Utils.toHex(cipherText));

        // decryption step
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] plainText = cipher.doFinal(cipherText);
        System.out.println("plain : " + Utils.toHex(plainText));
    }

    /**
     * RSA public/private exponent manually generated
     */
    static void encryptDecryptWithPublicPrivateRSAKeysWithExponentManuallyGenerated() throws Exception {
        int keySize = 512;
        SecureRandom random = new SecureRandom();
        // Choose two distinct prime numbers p and q.
        BigInteger p = BigInteger.probablePrime(keySize / 2, random);
        BigInteger q = BigInteger.probablePrime(keySize / 2, random);
        // Compute n = pq (modulus)
        BigInteger modulus = p.multiply(q);
        // Compute φ(n) = φ(p)φ(q) = (p − 1)(q − 1) = n - (p + q -1), where φ is Euler's totient function.
        // and choose an integer e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1; i.e., e and φ(n) are coprime.
        BigInteger m = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        BigInteger publicExponent = getCoprime(m, random);
        // Determine d as d ≡ e−1 (mod φ(n)); i.e., d is the multiplicative inverse of e (modulo φ(n)).
        BigInteger privateExponent = publicExponent.modInverse(m);

        Cipher cipher = Cipher.getInstance("RSA");

        RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
        RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(modulus, privateExponent);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
        RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);

        System.out.println("input : " + Utils.toHex(INPUT));

        // encryption step
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] cipherText = cipher.doFinal(INPUT);
        System.out.println("cipher: " + Utils.toHex(cipherText));

        // decryption step
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] plainText = cipher.doFinal(cipherText);
        System.out.println("plain : " + Utils.toHex(plainText));
    }

    /**
     * Symmetric key exchange process using asymmetric key exchange
     */
    static void encryptDecryptWrappedSymmetricWithAsymmetricKey() throws Exception {
        SecureRandom random = Utils.createFixedRandom();

        // create the RSA Key
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024, random);
        KeyPair pair = keyPairGenerator.generateKeyPair();
        Key publicKey = pair.getPublic();
        Key privateKey = pair.getPrivate();
        System.out.println("input : " + Utils.toHex(INPUT));

        // create the symmetric key and iv
        Key symmetricKey = Utils.createKeyForAES(128, random);
        IvParameterSpec symmetricIvSpec = Utils.createIvForAES(0, random);

        // symmetric key/iv wrapping step
        Cipher asymmetricCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        asymmetricCipher.init(Cipher.ENCRYPT_MODE, publicKey, random);
        byte[] keyBlock = asymmetricCipher.doFinal(packKeyAndIv(symmetricKey, symmetricIvSpec));

        // encryption step
        Cipher symmetricCipher = Cipher.getInstance("AES/CTR/NoPadding");
        symmetricCipher.init(Cipher.ENCRYPT_MODE, symmetricKey, symmetricIvSpec);
        byte[] cipherText = symmetricCipher.doFinal(INPUT);
        System.out.println("keyBlock length : " + keyBlock.length);
        System.out.println("cipherText length : " + cipherText.length);

        // symmetric key/iv unwrapping step
        asymmetricCipher.init(Cipher.DECRYPT_MODE, privateKey);
        Object[] keyIv = unpackKeyAndIV(asymmetricCipher.doFinal(keyBlock));

        // decryption step
        symmetricCipher.init(Cipher.DECRYPT_MODE, (Key) keyIv[0], (IvParameterSpec) keyIv[1]);
        byte[] plainText = symmetricCipher.doFinal(cipherText);
        System.out.println("plain : " + Utils.toHex(plainText));
    }

    /**
     * Pb is that input is converted to Integer so "00" are escaped on conversion so we use padding to keep them
     * Example here with PKCS1 Padding
     */
    static void encryptDecryptWithPublicPrivatePKCS1Padding() throws Exception {
        // TODO try with bigger input (text or...)
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        // TODO implement it or not
        SecureRandom random = Utils.createFixedRandom();

        // create the keys
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(512, random);
        KeyPair pair = generator.generateKeyPair();
        Key publicKey = pair.getPublic();
        Key privateKey = pair.getPrivate();

        System.out.println("input : " + Utils.toHex(INPUT));

        // encryption step
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, random);
        byte[] cipherText = cipher.doFinal(INPUT);
        System.out.println("cipher: " + Utils.toHex(cipherText));

        // decryption step
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] plainText = cipher.doFinal(cipherText);
        System.out.println("plain : " + Utils.toHex(plainText));
    }

    static void encryptDecryptWithPublicPrivateOAEPPadding() throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
        SecureRandom random = Utils.createFixedRandom();

        // create the keys
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(512, random);
        KeyPair pair = generator.generateKeyPair();
        Key pubKey = pair.getPublic();
        Key privKey = pair.getPrivate();

        System.out.println("input : " + Utils.toHex(INPUT));

        // encryption step
        cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);
        byte[] cipherText = cipher.doFinal(INPUT);
        System.out.println("cipher: " + Utils.toHex(cipherText));

        // decryption step
        cipher.init(Cipher.DECRYPT_MODE, privKey);
        byte[] plainText = cipher.doFinal(cipherText);
        System.out.println("plain : " + Utils.toHex(plainText));
    }

    private static BigInteger getCoprime(BigInteger m, SecureRandom random) {
        int length = m.bitLength() - 1;
        BigInteger e = BigInteger.probablePrime(length, random);
        while (!(m.gcd(e)).equals(BigInteger.ONE)) {
            e = BigInteger.probablePrime(length, random);
        }
        return e;
    }

    private static byte[] packKeyAndIv(Key key, IvParameterSpec ivSpec) throws IOException {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        bOut.write(ivSpec.getIV());
        bOut.write(key.getEncoded());

        return bOut.toByteArray();
    }

    private static Object[] unpackKeyAndIV(byte[] data) {
        return new Object[]{new SecretKeySpec(data, 16, data.length - 16, "AES"), new IvParameterSpec(data, 0, 16)};
    }

    public static void main(String... args) throws Exception {
        encryptDecryptWithPublicPrivateRSAKeysGenerated();
        //        encryptDecryptWithPublicPrivateRSAKeysWithExponentManuallyGenerated();
        //        encryptDecryptWithPublicPrivatePKCS1Padding();
        //        encryptDecryptWithPublicPrivateOAEPPadding();
        //        encryptDecryptWrappedSymmetricWithAsymmetricKey();
    }

    private RSAAlgorithm() {
    }
}
