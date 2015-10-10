package com.adioss.security.asymmetric;

import java.io.*;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
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

    private static void encryptDecryptWithPublicPrivateRSAKeys() throws Exception {
        byte[] input = new byte[]{(byte) 0xbe, (byte) 0xef};
        Cipher cipher = Cipher.getInstance("RSA/None/NoPadding", "BC");

        // create the keys
        BigInteger modulus = new BigInteger("d46f473a2d746537de2056ae3092c451", 16);
        BigInteger publicExponent = new BigInteger("11", 16);
        BigInteger privateExponent = new BigInteger("57791d5430d593164082036ad8b29fb1", 16);

        RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
        RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(modulus, privateExponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
        RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
        RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);

        System.out.println("input : " + Utils.toHex(input));

        // encryption step
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] cipherText = cipher.doFinal(input);
        System.out.println("cipher: " + Utils.toHex(cipherText));

        // decryption step
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] plainText = cipher.doFinal(cipherText);
        System.out.println("plain : " + Utils.toHex(plainText));
    }

    /**
     * Pb is that input is converted to Integer so "00" are escaped on conversion so we use padding to keep them
     * Example here with PKCS1 Padding
     */
    private static void encryptDecryptWithPublicPrivatePKCS1Padding() throws Exception {
        // TODO try with bigger input (text or...)
        byte[] input = new byte[]{0x00, (byte) 0xbe, (byte) 0xef};
        Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding", "BC");
        // TODO implement it or not
        SecureRandom random = Utils.createFixedRandom();

        // create the keys
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
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

    private static void encryptDecryptWithPublicPrivateOAEPPadding() throws Exception {
        byte[] input = new byte[]{0x00, (byte) 0xbe, (byte) 0xef};
        Cipher cipher = Cipher.getInstance("RSA/None/OAEPWithSHA1AndMGF1Padding", "BC");
        SecureRandom random = Utils.createFixedRandom();

        // create the keys
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(386, random);
        KeyPair pair = generator.generateKeyPair();
        Key pubKey = pair.getPublic();
        Key privKey = pair.getPrivate();

        System.out.println("input : " + Utils.toHex(input));

        // encryption step
        cipher.init(Cipher.ENCRYPT_MODE, pubKey, random);
        byte[] cipherText = cipher.doFinal(input);
        System.out.println("cipher: " + Utils.toHex(cipherText));

        // decryption step
        cipher.init(Cipher.DECRYPT_MODE, privKey);
        byte[] plainText = cipher.doFinal(cipherText);
        System.out.println("plain : " + Utils.toHex(plainText));
    }

    private static byte[] packKeyAndIv(Key key, IvParameterSpec ivSpec) throws IOException {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        bOut.write(ivSpec.getIV());
        bOut.write(key.getEncoded());

        return bOut.toByteArray();
    }

    private static Object[] unpackKeyAndIV(byte[] data) {
        byte[] keyD = new byte[16];
        byte[] iv = new byte[data.length - 16];

        return new Object[]{new SecretKeySpec(data, 16, data.length - 16, "AES"), new IvParameterSpec(data, 0, 16)};
    }

    public static void encryptDecryptAsymmetricKey() throws Exception {
        byte[] input = new byte[]{0x00, (byte) 0xbe, (byte) 0xef};
        SecureRandom random = Utils.createFixedRandom();

        // create the RSA Key
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(1024, random);
        KeyPair pair = keyPairGenerator.generateKeyPair();
        Key publicKey = pair.getPublic();
        Key privateKey = pair.getPrivate();
        System.out.println("input            : " + Utils.toHex(input));

        // create the symmetric key and iv
        Key symmetricKey = Utils.createKeyForAES(256, random);
        IvParameterSpec symmetricIvSpec = Utils.createIvForAES(0, random);

        // symmetric key/iv wrapping step
        Cipher asymmetricCipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA1AndMGF1Padding", "BC");
        asymmetricCipher.init(Cipher.ENCRYPT_MODE, publicKey, random);
        byte[] keyBlock = asymmetricCipher.doFinal(packKeyAndIv(symmetricKey, symmetricIvSpec));

        // encryption step
        Cipher symmetricCipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
        symmetricCipher.init(Cipher.ENCRYPT_MODE, symmetricKey, symmetricIvSpec);
        byte[] cipherText = symmetricCipher.doFinal(input);
        System.out.println("keyBlock length  : " + keyBlock.length);
        System.out.println("cipherText length: " + cipherText.length);

        // symmetric key/iv unwrapping step
        asymmetricCipher.init(Cipher.DECRYPT_MODE, privateKey);
        Object[] keyIv = unpackKeyAndIV(asymmetricCipher.doFinal(keyBlock));

        // decryption step
        symmetricCipher.init(Cipher.DECRYPT_MODE, (Key) keyIv[0], (IvParameterSpec) keyIv[1]);
        byte[] plainText = symmetricCipher.doFinal(cipherText);
        System.out.println("plain            : " + Utils.toHex(plainText));
    }

    public static void main(String... args) throws Exception {
        encryptDecryptWithPublicPrivateRSAKeys();
        encryptDecryptWithPublicPrivatePKCS1Padding();
        encryptDecryptWithPublicPrivateOAEPPadding();
        encryptDecryptAsymmetricKey();
    }
}
