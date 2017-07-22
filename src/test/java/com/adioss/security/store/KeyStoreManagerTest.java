package com.adioss.security.store;

import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import javax.crypto.*;
import javax.security.auth.x500.*;
import org.junit.After;
import org.junit.Assert;
import org.junit.Test;
import com.adioss.security.Utils;

import static com.adioss.security.certificate.CertificateGenerator.*;
import static java.util.Arrays.*;

public class KeyStoreManagerTest {
    private static final char[] DEFAULT_PASSWORD = "changeit".toCharArray();
    private static final String TO_REMOVE_JKS_FILE_NAME = "/toRemove.jks";

    @After
    public void tearDown() throws Exception {
        URL resource = getClass().getResource(TO_REMOVE_JKS_FILE_NAME);
        if (resource != null) {
            Path jksToDelete = Paths.get(resource.toURI());
            if (Files.exists(jksToDelete)) {
                Files.delete(jksToDelete);
            }
        }
    }

    @Test
    public void shouldCreateKeyStoreWithOneKeyEntry() throws Exception {
        // Given
        String endEntityAlias = "end";
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        // Generate root CA
        KeyPair caRootKeyPair = keyPairGenerator.generateKeyPair();
        X509Certificate caRootCertificate = generateRootCert(caRootKeyPair, "CN=Root CA Certificate");
        X500PrivateCredential rootPrivateCredential = new X500PrivateCredential(caRootCertificate, caRootKeyPair.getPrivate(), "root");
        // Generate standard certificate to revoke
        KeyPair intermediateKeyPair = keyPairGenerator.generateKeyPair();
        X509Certificate intermediateCertificate = generateIntermediateCA(intermediateKeyPair, caRootKeyPair, caRootCertificate,
                                                                         "CN=Test Intermediate Certificate");
        // Generate standard certificate not revoked
        KeyPair endEntityKeyPair = keyPairGenerator.generateKeyPair();
        X509Certificate endEntityCertificate = generateEndEntityCert(endEntityKeyPair, intermediateKeyPair, intermediateCertificate,
                                                                     "CN=End Certificate Not Revoked");
        X500PrivateCredential endEntityPrivateCredential = new X500PrivateCredential(endEntityCertificate, endEntityKeyPair.getPrivate(), endEntityAlias);

        // When
        KeyStore store = KeyStoreManager.createKeyStoreWithOnePrivateKeyEntry(endEntityPrivateCredential, DEFAULT_PASSWORD, rootPrivateCredential,
                                                                              asList(endEntityCertificate, intermediateCertificate, caRootCertificate));

        // Then
        Assert.assertNotNull(store);
        Assert.assertNotNull(store.getKey(endEntityAlias, DEFAULT_PASSWORD));
        // And
        KeyStore.Builder builder = KeyStore.Builder.newInstance(store, new KeyStore.PasswordProtection(DEFAULT_PASSWORD));
        store = builder.getKeyStore();
        KeyStore.ProtectionParameter param = builder.getProtectionParameter(endEntityAlias);
        KeyStore.Entry entry = store.getEntry(endEntityAlias, param);
        Assert.assertNotNull(entry);
    }

    @Test
    public void shouldOpenAndSaveJksStore() throws Exception {
        // Given
        Path path = Paths.get(getClass().getResource("/test.keystore.jks").toURI());

        // When
        KeyStore store = KeyStoreManager.open(path.toString(), "JKS", DEFAULT_PASSWORD);
        String outputPath = path.getParent().toAbsolutePath().toString() + TO_REMOVE_JKS_FILE_NAME;
        KeyStoreManager.save(store, outputPath, DEFAULT_PASSWORD);
        KeyStore copiedStore = KeyStoreManager.open(outputPath, "JKS", DEFAULT_PASSWORD);

        // Then
        Assert.assertNotNull(store);
        Assert.assertTrue(store.aliases().hasMoreElements());
        // And
        Assert.assertNotNull(copiedStore);
        Assert.assertTrue(copiedStore.aliases().hasMoreElements());
    }

    @Test
    public void shouldCreateJceksStoreWithOneSecretKeyStoredInside() throws Exception {
        // Given
        SecretKey key = (SecretKey) Utils.createKeyForAES(new SecureRandom());
        String secretKeyAlias = "mySecretKey";

        // When
        KeyStore store = KeyStoreManager.createKeyStoreWithOneSecretKeyEntry(secretKeyAlias, key, DEFAULT_PASSWORD);

        // Then
        Assert.assertNotNull(store);
        Assert.assertTrue(store.aliases().hasMoreElements());
        Key retrieved = store.getKey(secretKeyAlias, DEFAULT_PASSWORD);
        Assert.assertNotNull(retrieved);
        Assert.assertTrue(retrieved instanceof SecretKey);
    }
}
