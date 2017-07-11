package com.adioss.security.certificate;

import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathValidator;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.*;
import javax.security.auth.x500.*;

import static java.util.Arrays.*;
import static java.util.Collections.*;

class CertificatePathValidator {

    /**
     * Validate paths of certificate chain of trust using a {@link CertPathBuilder}:
     * if able to build a {@link PKIXCertPathBuilderResult} without exceptions, path is basically verified
     *
     * @param endEntityCertificate the {@link X509Certificate} to validate
     * @param trustedRootCert the {@link X509Certificate} root CA issuer certificate used to create chain of trust, used as {@link TrustAnchor}. Must be self-signed.
     * @param intermediateCerts list of {@link X509Certificate} intermediate CA certificates used to create chain of trust, added to {@link PKIXParameters#addCertStore}. Can not be self-signed.
     */
    static boolean validatePathWithBuilder(X509Certificate endEntityCertificate, X509Certificate trustedRootCert, X509Certificate... intermediateCerts)
            throws Exception {
        try {
            // Create the selector that specifies the certificate that we want to match
            X509CertSelector certSelector = new X509CertSelector();
            certSelector.setCertificate(endEntityCertificate);

            // Create the trust anchors (set of root CA certificates)
            if (!isSelfSigned(trustedRootCert)) {
                throw new RuntimeException("'trustedRootCert' must be self signed.");
            }
            Set<TrustAnchor> trustAnchors = new HashSet<>();
            trustAnchors.add(new TrustAnchor(trustedRootCert, null));

            // Configure the PKIX certificate builder algorithm parameters
            PKIXBuilderParameters pkixBuilderParameters = new PKIXBuilderParameters(trustAnchors, certSelector);

            // Disable CRL checks
            pkixBuilderParameters.setRevocationEnabled(false);

            // Specify a list of intermediate certificates
            if (intermediateCerts != null && intermediateCerts.length > 0) {
                List<Object> checkedIntermediateCerts = new ArrayList<>();
                for (X509Certificate intermediateCert : intermediateCerts) {
                    if (!isSelfSigned(trustedRootCert)) {
                        throw new RuntimeException("'intermediateCert' can not be self signed.");
                    }
                    checkedIntermediateCerts.add(intermediateCert);
                }
                CertStore intermediateCertStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(checkedIntermediateCerts));
                pkixBuilderParameters.addCertStore(intermediateCertStore);
            }

            // Build and verify the certification chain
            CertPathBuilder certPathBuilder = CertPathBuilder.getInstance("PKIX");
            PKIXCertPathBuilderResult pathBuilderResult = (PKIXCertPathBuilderResult) certPathBuilder.build(pkixBuilderParameters);
            return pathBuilderResult != null;
        } catch (Exception e) {
            // Impossible to build path correctly
            e.printStackTrace();
            return false;
        }
    }

    @SuppressWarnings("SameParameterValue")
    static boolean validatePathWithBuilder(String endEntityCertificate, X509Certificate... certificates) throws Exception {
        try {
            // Create the selector that specifies the certificate that we want to match
            X509CertSelector certSelector = new X509CertSelector();
            certSelector.setSubject(new X500Principal(endEntityCertificate).getEncoded());

            // Create the trust anchor (here for simplicity, only one root CA certificate should be provided)
            Optional<X509Certificate> trustedRootCert = Arrays.stream(certificates).filter(CertificatePathValidator::isSelfSigned).findFirst();
            if (!trustedRootCert.isPresent()) {
                throw new RuntimeException("'trustedRootCert' must be present / self signed.");
            }
            Set<TrustAnchor> trustAnchors = new HashSet<>();
            trustAnchors.add(new TrustAnchor(trustedRootCert.get(), null));

            // Configure the PKIX certificate builder algorithm parameters
            PKIXBuilderParameters pkixBuilderParameters = new PKIXBuilderParameters(trustAnchors, certSelector);

            // Disable CRL checks
            pkixBuilderParameters.setRevocationEnabled(false);

            // Specify a list of certificates (+ the on to retrieve with the selector)
            if (certificates.length > 0) {
                CertStore intermediateCertStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(asList(certificates)));
                pkixBuilderParameters.addCertStore(intermediateCertStore);
            }

            // Build and verify the certification chain
            CertPathBuilder certPathBuilder = CertPathBuilder.getInstance("PKIX");
            PKIXCertPathBuilderResult pathBuilderResult = (PKIXCertPathBuilderResult) certPathBuilder.build(pkixBuilderParameters);
            return pathBuilderResult != null;
        } catch (Exception e) {
            // Impossible to build path correctly
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Validate paths of certificate chain of trust: retrieve issuer by subjectDN and use {@link CertPathValidator#validate} to validate certificate.
     * Recursively validate issuers.
     *
     * @param endEntityCertificate the {@link X509Certificate} to validate
     * @param keyStore {@link KeyStore} that contain the list of all {@link X509Certificate} issuers used to create chain of trust.
     */
    static boolean manuallyValidatePaths(X509Certificate endEntityCertificate, KeyStore keyStore) throws Exception {
        Enumeration<String> alias = keyStore.aliases();

        List<X509Certificate> certs = new ArrayList<>();
        while (alias.hasMoreElements()) {
            X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias.nextElement());
            certs.add(certificate);
        }

        return manuallyValidatePaths(endEntityCertificate, certs);
    }

    /**
     * Validate paths of certificate chain of trust: retrieve issuer by subjectDN and use {@link CertPathValidator#validate} to validate certificate.
     * Recursively validate issuers.
     *
     * @param endEntityCertificate the {@link X509Certificate} to validate
     * @param trustedCerts list of all {@link X509Certificate} issuers used to create chain of trust.
     */
    static boolean manuallyValidatePaths(X509Certificate endEntityCertificate, List<X509Certificate> trustedCerts) {
        Optional<X509Certificate> trusted = trustedCerts.stream().filter(tc -> endEntityCertificate.getIssuerDN().equals(tc.getSubjectDN())).findFirst();
        if (trusted.isPresent()) {
            X509Certificate issuerCertificate = trusted.get();
            // Validate path: certificate validated by issuer certificate
            if (!validatePath(endEntityCertificate, issuerCertificate)) {
                return false;
            }
            // If trusted/issuer certificate is self signed, we are at the top of paths validation (root CA)
            if (isSelfSigned(issuerCertificate) && validatePath(issuerCertificate, issuerCertificate)) {
                //System.out.println(client.getSubjectDN() + " validated by root:" + issuerCertificate.getSubjectX500Principal().getName());
                return true;
            }

            // Validate issuer
            //System.out.println(client.getSubjectDN() + " validated by:" + issuerCertificate.getSubjectX500Principal().getName());
            return manuallyValidatePaths(issuerCertificate, trustedCerts);
        }
        return false;
    }

    private static boolean validatePath(X509Certificate client, X509Certificate trustedCert) {
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX");
            // Certificate to validate
            CertPath certPath = certificateFactory.generateCertPath(singletonList(client));

            // Add the cert of CA that signed the certificate to validate
            TrustAnchor trustAnchor = new TrustAnchor(trustedCert, null);
            Set<TrustAnchor> anchors = Collections.singleton(trustAnchor);
            PKIXParameters pkixParameters = new PKIXParameters(anchors);
            pkixParameters.setRevocationEnabled(false);

            // Validation
            certPathValidator.validate(certPath, pkixParameters);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    private static boolean isSelfSigned(X509Certificate cert) {
        try {
            PublicKey key = cert.getPublicKey();
            cert.verify(key);
            return true;
        } catch (Exception sigEx) {
            return false;
        }
    }

    private CertificatePathValidator() {
    }
}
