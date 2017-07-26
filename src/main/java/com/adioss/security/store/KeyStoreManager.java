package com.adioss.security.store;

import java.io.*;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.*;
import javax.crypto.*;
import javax.security.auth.x500.*;
import com.google.common.annotations.VisibleForTesting;

import static java.security.KeyStore.*;

class KeyStoreManager {

    @VisibleForTesting
    static KeyStore createDefaultTypeKeyStore() throws Exception {
        KeyStore store = KeyStore.getInstance(getDefaultType());
        // initialize
        store.load(null, null);
        return store;
    }

    @VisibleForTesting
    static KeyStore createPKCS12KeyStore() throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        // initialize
        store.load(null, null);
        return store;
    }

    @VisibleForTesting
    static KeyStore createJCEKSKeyStore() throws Exception {
        KeyStore store = KeyStore.getInstance("JCEKS");
        // initialize
        store.load(null, null);
        return store;
    }

    /**
     * Add a {@link PrivateKey} inside a store
     *
     * @param caRootCertificate the {@link TrustedCertificateEntry} that signed the entry
     */
    @VisibleForTesting
    static void addCertificateEntry(KeyStore store, X500PrivateCredential caRootCertificate) throws Exception {
        store.setEntry(caRootCertificate.getAlias(), new TrustedCertificateEntry(caRootCertificate.getCertificate()), null);
        // equivalent to:
        // store.setCertificateEntry(caRootCertificate.getAlias(), caRootCertificate.getCertificate());
    }

    /**
     * Add a {@link PrivateKeyEntry} inside a store
     *
     * @param endEntityEntry the key entry to append
     * @param endEntityKeyPassword the password for entry to append
     * @param chains the certificate chain for the corresponding public key
     */
    @VisibleForTesting
    static void addPrivateKeyEntry(KeyStore store, X500PrivateCredential endEntityEntry, char[] endEntityKeyPassword, List<Certificate> chains)
            throws Exception {
        store.setEntry(endEntityEntry.getAlias(), new PrivateKeyEntry(endEntityEntry.getPrivateKey(), (Certificate[]) chains.toArray()),
                       new PasswordProtection(endEntityKeyPassword));
        // equivalent to:
        // store.setKeyEntry(endEntityEntry.getAlias(), endEntityEntry.getPrivateKey(), endEntityKeyPassword, (Certificate[]) chains.toArray());
    }

    /**
     * Add a {@link PrivateKeyEntry} inside a store
     *
     * @param secretKeyAlias the secret key alias
     * @param secretKey the {@link SecretKey}
     * @param secretKeyPassword the secret key password
     */
    @VisibleForTesting
    static void addSecretKeyEntry(KeyStore store, String secretKeyAlias, SecretKey secretKey, char[] secretKeyPassword) throws Exception {
        store.setEntry(secretKeyAlias, new KeyStore.SecretKeyEntry(secretKey), new KeyStore.PasswordProtection(secretKeyPassword));
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
