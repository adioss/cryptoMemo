package com.adioss.security.store;

import java.io.*;
import java.nio.file.Paths;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.*;
import javax.crypto.*;
import javax.security.auth.x500.*;
import com.adioss.security.Utils;
import com.google.common.annotations.VisibleForTesting;

import static java.security.KeyStore.*;

class KeyStoreManager {

    /**
     * Create a JKS store with one {@link PrivateKey} inside
     *
     * @param endEntityEntry the key entry to append
     * @param endEntityKeyPassword the password for entry to append
     * @param caRootCertificate the {@link TrustedCertificateEntry} that signed the entry
     * @param chains the certificate chain for the corresponding public key
     * @return a {@link KeyStore}
     */
    @VisibleForTesting
    static KeyStore createKeyStoreWithOnePrivateKeyEntry(X500PrivateCredential endEntityEntry, char[] endEntityKeyPassword,
                                                         X500PrivateCredential caRootCertificate, List<Certificate> chains) throws Exception {
        KeyStore store = getInstance(getDefaultType());
        // initialize
        store.load(null, null);
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        // set the entries
        store.setEntry(caRootCertificate.getAlias(), new KeyStore.TrustedCertificateEntry(caRootCertificate.getCertificate()), null);
        store.setEntry(endEntityEntry.getAlias(), new KeyStore.PrivateKeyEntry(endEntityEntry.getPrivateKey(), (Certificate[]) chains.toArray()),
                       new KeyStore.PasswordProtection(endEntityKeyPassword));

        // equivalent to:
        //
        // store.setCertificateEntry(caRootCertificate.getAlias(), caRootCertificate.getCertificate());
        // store.setKeyEntry(endEntityEntry.getAlias(), endEntityEntry.getPrivateKey(), endEntityKeyPassword, (Certificate[]) chains.toArray());

        return store;
    }

    /**
     * Create a JCEKS store with one {@link SecretKeyEntry} inside (check {@link Utils#createKeyForAES} to create one)
     *
     * @param secretKeyAlias the alias
     * @param secretKey the {@link SecretKey}
     * @param secretKeyPassword the password for the key
     * @return a {@link KeyStore}
     */
    @VisibleForTesting
    static KeyStore createKeyStoreWithOneSecretKeyEntry(String secretKeyAlias, SecretKey secretKey, char[] secretKeyPassword) throws Exception {
        KeyStore store = getInstance("JCEKS");
        // initialize
        store.load(null, null);

        // set the entries
        store.setEntry(secretKeyAlias, new KeyStore.SecretKeyEntry(secretKey), new KeyStore.PasswordProtection(secretKeyPassword));

        return store;
    }

    /**
     * Open a {@link KeyStore} of the given type (JKS, PKCS12 etc...)
     *
     * @param storePath the path of the keystore
     * @param storeType the type of the keystore (JKS, PKCS12 etc...)
     * @param storePassword the password to open the keystore
     * @return opened {@link KeyStore}
     */
    @VisibleForTesting
    static KeyStore open(String storePath, String storeType, char[] storePassword) throws Exception {
        KeyStore store = KeyStore.getInstance(storeType);
        try (FileInputStream fileInputStream = new FileInputStream(Paths.get(storePath).toFile())) {
            store.load(fileInputStream, storePassword);
        }
        return store;
    }

    /**
     * Save a {@link KeyStore} to a given path
     *
     * @param store {@link KeyStore} to save
     * @param outputPath the path to save the keystore
     * @param outputPassword the keystore password
     */
    @VisibleForTesting
    static void save(KeyStore store, String outputPath, char[] outputPassword) throws Exception {
        try (FileOutputStream fileOutputStream = new FileOutputStream(Paths.get(outputPath).toFile())) {
            // save the store
            store.store(fileOutputStream, outputPassword);
        }
    }

    private KeyStoreManager() {
    }
}
