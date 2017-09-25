package com.adioss.security.certificate;

import java.net.URI;
import java.security.cert.X509Certificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.annotations.VisibleForTesting;
import sun.security.provider.certpath.OCSP;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AuthorityInfoAccessExtension;
import sun.security.x509.X509CertImpl;

import static sun.security.provider.certpath.OCSP.RevocationStatus.CertStatus.GOOD;

/**
 * Check status of a certificate using an OCSP server (Online Certificate Status Protocol)
 */
class OCSPChecker {
    private static final Logger LOG = LoggerFactory.getLogger(OCSPChecker.class);
    private static final String CERTIFICATE_AUTHORITY_INFORMATION_ACCESS_OID = "1.3.6.1.5.5.7.1.1";

    /**
     * Validate a certificate through an OCSP server
     *
     * @param toCheck {@link X509Certificate} to check
     * @param checker {@link X509Certificate} that contains the {@link AuthorityInfoAccessExtension} with OCSP server access location
     * @return {@code true} if certificate validated by OCSP server
     */
    @VisibleForTesting
    static boolean isCertificateStatusGood(X509Certificate toCheck, X509Certificate checker) throws Exception {
        AuthorityInfoAccessExtension extension = (AuthorityInfoAccessExtension) ((X509CertImpl) checker)
                .getExtension(new ObjectIdentifier(CERTIFICATE_AUTHORITY_INFORMATION_ACCESS_OID));
        LOG.info("Check over OCSP server: " + extension.getAccessDescriptions());

        OCSP.RevocationStatus check = OCSP.check(toCheck, checker, new URI("http://ocsp.digicert.com"), null, null);
        OCSP.RevocationStatus.CertStatus certStatus = check.getCertStatus();
        return certStatus == GOOD;
    }

    private OCSPChecker() {
    }
}
