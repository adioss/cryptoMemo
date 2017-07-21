package com.adioss.security.certificate;

import java.io.*;
import java.security.cert.X509Certificate;
import org.junit.Test;
import com.adioss.security.Utils;

import static org.junit.Assert.assertTrue;

public class OCSPCheckerTest {
    @Test
    public void shouldCheckCertificateNonRevocationThroughOCSPServer() throws Exception {
        try (InputStream githubCerAsStream = getClass().getResourceAsStream("/github.cer");
             InputStream digiCertIntermediateCerAsStream = getClass().getResourceAsStream("/digiCertIntermediate.cer")) {
            X509Certificate githubCertificate = Utils.openDerFile(githubCerAsStream);
            X509Certificate digiCertIntermediateCertificate = Utils.openDerFile(digiCertIntermediateCerAsStream);
            assertTrue(OCSPChecker.isCertificateStatusGood(githubCertificate, digiCertIntermediateCertificate));
        }
    }
}
