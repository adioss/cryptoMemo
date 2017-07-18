package com.adioss.security;

import java.security.Provider;
import java.security.Security;
import javax.crypto.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * To append new cipher provider,
 * - add jar into jre\lib\ext
 * - modify java.security and add a new security provider. For ex: security.provider.11=org.bouncycastle.jce.provider.BouncyCastleProvider
 */
class ExternalProvider {
    private static final Logger LOG = LoggerFactory.getLogger(ExternalProvider.class);

    /**
     * Test the external provider installation
     */
    static void testExternalProviderInstallation() {
        String providerName = "BC";

        if (Security.getProvider(providerName) == null) {
            LOG.debug(providerName + " provider not installed");
        } else {
            LOG.debug(providerName + " is installed.");
        }
    }

    /**
     * Here as BC provider as less priority than default jvm(security.provider.11=org.bouncycastle.jce.provider.BouncyCastleProvider)
     * when we call blowfish cipher, default is select until we specified it
     */
    static void testProviderPriority() throws Exception {
        Cipher cipher = Cipher.getInstance("Blowfish/ECB/NoPadding");
        LOG.debug(cipher.getProvider().getName());

        cipher = Cipher.getInstance("Blowfish/ECB/NoPadding", "BC");
        LOG.debug(cipher.getProvider().getName());
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
            LOG.debug(factoryClass + ": " + name);
        }
    }

    private ExternalProvider() {
    }
}
