package com.adioss.security.certificate;

import java.io.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import static com.adioss.security.certificate.CertificateGenerator.*;
import static com.adioss.security.certificate.CertificatePathValidator.*;
import static java.util.Arrays.*;
import static org.junit.Assert.*;

public class CertificateValidationTest {
    private static final String DEFAULT_PASSWORD = "changeit";

    @BeforeClass
    public static void setUp() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
    }

    @AfterClass
    public static void tearDown() throws Exception {
        Security.removeProvider("BC");
    }

    @Test
    public void shouldGenerateX509V1Certificate() throws Exception {
        // Given a keypair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // When generate a X509 certificate V0
        X509Certificate x509Certificate = generateX509V1Certificate(keyPair);

        // Then is validated by public key
        x509Certificate.verify(keyPair.getPublic());
    }

    @Test
    public void shouldValidateProgrammaticallyGeneratedX509V3ChainedCertificates() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);

        // Generate root CA
        KeyPair caRootKeyPair = keyPairGenerator.generateKeyPair();
        X509Certificate caRootCertificate = generateRootCert(caRootKeyPair, "CN=Root CA Certificate");
        caRootCertificate.verify(caRootKeyPair.getPublic());

        // Generate another root CA
        KeyPair fakeRootKeyPair = keyPairGenerator.generateKeyPair();
        X509Certificate fakeRootCertificate = generateRootCert(fakeRootKeyPair, "CN=Fake Root CA Certificate");

        // Generate intermediate CA
        KeyPair intermediateKeyPair = keyPairGenerator.generateKeyPair();
        X509Certificate intermediateCertificate = generateIntermediateCA(intermediateKeyPair, caRootKeyPair, caRootCertificate,
                                                                         "CN=Test Intermediate Certificate");
        intermediateCertificate.verify(caRootKeyPair.getPublic());

        // Generate another intermediate certificate
        X509Certificate otherIntermediateCertificate = generateIntermediateCA(keyPairGenerator.generateKeyPair(), caRootKeyPair, caRootCertificate,
                                                                              "CN=Test Other Intermediate Certificate");

        // Generate intermediate CA with fakeRootCertificate
        X509Certificate fakeIntermediateCertificate = generateIntermediateCA(keyPairGenerator.generateKeyPair(), fakeRootKeyPair, fakeRootCertificate,
                                                                             "CN=Fake Intermediate Certificate");

        // Generate standard certificate
        KeyPair standardKeyPair = keyPairGenerator.generateKeyPair();
        X509Certificate endEntityCertificate = generateEndEntityCert(standardKeyPair, intermediateKeyPair, intermediateCertificate, "CN=End Certificate");
        endEntityCertificate.verify(intermediateKeyPair.getPublic());

        assertTrue(manuallyValidatePaths(endEntityCertificate, new ArrayList<>(asList(caRootCertificate, intermediateCertificate))));
        assertFalse(manuallyValidatePaths(endEntityCertificate, new ArrayList<>(asList(fakeRootCertificate, intermediateCertificate))));
        assertFalse(manuallyValidatePaths(endEntityCertificate, new ArrayList<>(asList(caRootCertificate, fakeIntermediateCertificate))));

        assertTrue(validatePathWithBuilder(endEntityCertificate, caRootCertificate, intermediateCertificate));
        assertTrue(validatePathWithBuilder(endEntityCertificate, caRootCertificate, otherIntermediateCertificate, intermediateCertificate));
        assertFalse(validatePathWithBuilder(endEntityCertificate, caRootCertificate));
        assertFalse(validatePathWithBuilder(endEntityCertificate, intermediateCertificate));
        assertFalse(validatePathWithBuilder(endEntityCertificate, fakeRootCertificate, intermediateCertificate));
        assertFalse(validatePathWithBuilder(endEntityCertificate, caRootCertificate, otherIntermediateCertificate));
        assertFalse(validatePathWithBuilder(endEntityCertificate, caRootCertificate, fakeIntermediateCertificate));
        assertTrue(validatePathWithBuilder(endEntityCertificate, caRootCertificate, intermediateCertificate, fakeIntermediateCertificate));
        assertTrue(validatePathWithBuilder("CN=End Certificate", caRootCertificate, endEntityCertificate, intermediateCertificate));
    }

    @Test
    public void shouldValidateGeneratedX509V3ChainedCertificatesFromJKS() throws Exception {
        try (InputStream resourceAsStream = getClass().getResourceAsStream("/generated/signedBySubIntermediate.jks")) {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(resourceAsStream, DEFAULT_PASSWORD.toCharArray());
            X509Certificate certificate = (X509Certificate) keyStore.getCertificate("my-alias");

            assertTrue(manuallyValidatePaths(certificate, keyStore));
        }
    }

    @Test
    public void shouldDetectRevokedCertificateUsingCRL() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        // Generate root CA
        KeyPair caRootKeyPair = keyPairGenerator.generateKeyPair();
        X509Certificate caRootCertificate = generateRootCert(caRootKeyPair, "CN=Root CA Certificate");
        // Generate standard certificate to revoke
        KeyPair standardKeyPairRevoked = keyPairGenerator.generateKeyPair();
        X509Certificate endEntityCertificateRevoked = generateEndEntityCert(standardKeyPairRevoked, caRootKeyPair, caRootCertificate,
                                                                            "CN=End Certificate Revoked");
        KeyPair standardKeyPairNotRevoked = keyPairGenerator.generateKeyPair();
        X509Certificate endEntityCertificateNotRevoked = generateEndEntityCert(standardKeyPairNotRevoked, caRootKeyPair, caRootCertificate,
                                                                               "CN=End Certificate Not Revoked");

        // Create a CRL for this CA
        X509CRL crl = CRLGenerator.createCRL(caRootCertificate, caRootKeyPair, endEntityCertificateRevoked.getSerialNumber());
        // CRL checked by issuer
        crl.verify(caRootCertificate.getPublicKey());
        // certificate revoked is found
        assertNotNull(crl.getRevokedCertificate(endEntityCertificateRevoked));
        // certificate not revoked is absent
        assertNull(crl.getRevokedCertificate(endEntityCertificateNotRevoked));
    }
}
