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
import java.security.Security;
import java.security.cert.X509Certificate;
import javax.crypto.*;
import javax.security.auth.x500.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import com.adioss.security.Utils;

import static com.adioss.security.certificate.CertificateGenerator.*;
import static java.util.Arrays.*;

@SuppressWarnings("Duplicates")
public class KeyStoreManagerTest {
    private static final char[] DEFAULT_PASSWORD = "changeit".toCharArray();
    private static final String TO_REMOVE_JKS_FILE_NAME = "/toRemove.jks";
    private static final String ROOT_CERTIFICATE_ALIAS = "root";
    private static final String END_ENTITY_ALIAS = "end";

    private X509Certificate m_caRootCertificate;
    private X500PrivateCredential m_rootPrivateCredential;
    private X509Certificate m_intermediateCertificate;
    private X500PrivateCredential m_endEntityPrivateCredential;
    private X509Certificate m_endEntityCertificate;

    @Before
    public void setUp() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        // Generate root CA
        KeyPair caRootKeyPair = keyPairGenerator.generateKeyPair();
        m_caRootCertificate = generateRootCert(caRootKeyPair, "CN=Root CA Certificate");
        m_rootPrivateCredential = new X500PrivateCredential(m_caRootCertificate, caRootKeyPair.getPrivate(), ROOT_CERTIFICATE_ALIAS);
        // Generate standard certificate to revoke
        KeyPair intermediateKeyPair = keyPairGenerator.generateKeyPair();
        m_intermediateCertificate = generateIntermediateCA(intermediateKeyPair, caRootKeyPair, m_caRootCertificate, "CN=Test Intermediate Certificate");
        // Generate standard certificate not revoked
        KeyPair endEntityKeyPair = keyPairGenerator.generateKeyPair();
        m_endEntityCertificate = generateEndEntityCert(endEntityKeyPair, intermediateKeyPair, m_intermediateCertificate, "CN=End Certificate Not Revoked");
        m_endEntityPrivateCredential = new X500PrivateCredential(m_endEntityCertificate, endEntityKeyPair.getPrivate(), END_ENTITY_ALIAS);
    }

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
    public void shouldCreateJKSKeyStoreWithOneKeyEntry() throws Exception {
        // Given
        KeyStore store = KeyStoreManager.createDefaultTypeKeyStore();

        // When
        KeyStoreManager.addCertificateEntry(store, m_rootPrivateCredential);
        KeyStoreManager.addPrivateKeyEntry(store, m_endEntityPrivateCredential, DEFAULT_PASSWORD,
                                           asList(m_endEntityCertificate, m_intermediateCertificate, m_caRootCertificate));

        // Then
        Assert.assertNotNull(store);
        Assert.assertNotNull(store.getKey(END_ENTITY_ALIAS, DEFAULT_PASSWORD));
        // And
        KeyStore.Builder builder = KeyStore.Builder.newInstance(store, new KeyStore.PasswordProtection(DEFAULT_PASSWORD));
        store = builder.getKeyStore();
        KeyStore.ProtectionParameter param = builder.getProtectionParameter(END_ENTITY_ALIAS);
        KeyStore.Entry entry = store.getEntry(END_ENTITY_ALIAS, param);
        Assert.assertNotNull(entry);
        // created with a TrustedCertificateEntry
        Assert.assertTrue(store.isCertificateEntry(ROOT_CERTIFICATE_ALIAS));
        // created with a PrivateKeyEntry
        Assert.assertFalse(store.isCertificateEntry(END_ENTITY_ALIAS));
    }

    @Test
    public void shouldCreatePKCS12KeyStoreWithOneKeyEntry() throws Exception {
        // Given
        KeyStore store = KeyStoreManager.createPKCS12KeyStore();

        // When
        KeyStoreManager.addCertificateEntry(store, m_rootPrivateCredential);
        KeyStoreManager.addPrivateKeyEntry(store, m_endEntityPrivateCredential, DEFAULT_PASSWORD,
                                           asList(m_endEntityCertificate, m_intermediateCertificate, m_caRootCertificate));

        // Then
        Assert.assertNotNull(store);
        Assert.assertNotNull(store.getKey(END_ENTITY_ALIAS, DEFAULT_PASSWORD));
        // And
        KeyStore.Builder builder = KeyStore.Builder.newInstance(store, new KeyStore.PasswordProtection(DEFAULT_PASSWORD));
        store = builder.getKeyStore();
        KeyStore.ProtectionParameter param = builder.getProtectionParameter(END_ENTITY_ALIAS);
        KeyStore.Entry entry = store.getEntry(END_ENTITY_ALIAS, param);
        Assert.assertNotNull(entry);
        // created with a TrustedCertificateEntry
        Assert.assertTrue(store.isCertificateEntry(ROOT_CERTIFICATE_ALIAS));
        // created with a PrivateKeyEntry
        Assert.assertFalse(store.isCertificateEntry(END_ENTITY_ALIAS));
    }

    @Test
    public void shouldCreatePKCS12BCKeyStoreWithOneKeyEntryWithoutPassword() throws Exception {
        // Given
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        KeyStore store = KeyStoreManager.createPKCS12BCKeyStore();

        // When
        // put a private key WITHOUT a password: only works on PKCS12 + BC (not JCE) implementation
        KeyStoreManager.addPrivateKeyEntry(store, m_endEntityPrivateCredential, asList(m_endEntityCertificate, m_intermediateCertificate, m_caRootCertificate));

        // Then
        Assert.assertNotNull(store);
        Assert.assertNotNull(store.getKey(END_ENTITY_ALIAS, DEFAULT_PASSWORD));
        // And
        KeyStore.Builder builder = KeyStore.Builder.newInstance(store, new KeyStore.PasswordProtection(DEFAULT_PASSWORD));
        store = builder.getKeyStore();
        KeyStore.ProtectionParameter param = builder.getProtectionParameter(END_ENTITY_ALIAS);
        KeyStore.Entry entry = store.getEntry(END_ENTITY_ALIAS, param);
        Assert.assertNotNull(entry);
        // created with a PrivateKeyEntry
        Assert.assertFalse(store.isCertificateEntry(END_ENTITY_ALIAS));
        Security.removeProvider(provider.getName());
    }

    @Test
    public void shouldCreateJCEKSStoreWithOneSecretKeyStoredInside() throws Exception {
        // Given
        SecretKey key = (SecretKey) Utils.createKeyForAES(new SecureRandom());
        String secretKeyAlias = "mySecretKey";

        // When
        KeyStore store = KeyStoreManager.createJCEKSKeyStore();
        KeyStoreManager.addSecretKeyEntry(store, secretKeyAlias, key, DEFAULT_PASSWORD);

        // Then
        Assert.assertNotNull(store);
        Assert.assertTrue(store.aliases().hasMoreElements());
        Key retrieved = store.getKey(secretKeyAlias, DEFAULT_PASSWORD);
        Assert.assertNotNull(retrieved);
        Assert.assertTrue(retrieved instanceof SecretKey);
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
}
