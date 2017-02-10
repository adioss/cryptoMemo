package com.adioss.security;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import javax.crypto.*;

/**
 * To append new cipher provider,
 * - add jar into jre\lib\ext
 * - modify java.security and add a new security provider. For ex: security.provider.11=org.bouncycastle.jce.provider.BouncyCastleProvider
 */
public class ExternalProviderTest {

    /**
     * Test the external provider installation
     */
    private static void testExternalProviderInstallation() {
        String providerName = "BC";

        if (Security.getProvider(providerName) == null) {
            System.out.println(providerName + " provider not installed");
        } else {
            System.out.println(providerName + " is installed.");
        }
    }

    /**
     * Here as BC provider as less priority than default jvm(security.provider.11=org.bouncycastle.jce.provider.BouncyCastleProvider)
     * when we call blowfish cipher, default is select until we specified it
     */
    private static void testProviderPriority() throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException {
        Cipher cipher = Cipher.getInstance("Blowfish/ECB/NoPadding");
        System.out.println(cipher.getProvider());

        cipher = Cipher.getInstance("Blowfish/ECB/NoPadding", "BC");
        System.out.println(cipher.getProvider());
    }

    /**
     * List all BouncyCastle provider capabilities: ciphers, key agreement, macs, message digests, signatures and other objects
     */
    private static void listBouncyCastleProviderCapabilities() {
        Provider provider = Security.getProvider("BC");
        for (Object o : provider.keySet()) {
            String entry = (String) o;
            // this indicates the entry actually refers to another entry
            if (entry.startsWith("Alg.Alias.")) {
                entry = entry.substring("Alg.Alias.".length());
            }
            String factoryClass = entry.substring(0, entry.indexOf('.'));
            String name = entry.substring(factoryClass.length() + 1);
            System.out.println(factoryClass + ": " + name);
        }
    }

    public static void main(String[] args) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        testExternalProviderInstallation();
        testProviderPriority();
        listBouncyCastleProviderCapabilities();
    }

    private ExternalProviderTest() {
    }
}
