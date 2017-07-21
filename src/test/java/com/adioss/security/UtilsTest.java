package com.adioss.security;

import java.io.*;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import org.junit.Test;
import com.adioss.security.certificate.CertificateValidationTest;
import com.google.common.base.Charsets;
import com.google.common.io.CharStreams;

import static org.junit.Assert.assertEquals;

public class UtilsTest {
    @Test
    public void shouldOpenDerFile() throws Exception {
        X509Certificate actual = Utils.openDerFile(getClass().getResourceAsStream("/generated/intermediateCA.cer"));
        assertEquals("CN=intermediateCA", actual.getSubjectDN().toString());
    }

    @Test
    public void shouldDumpCertRFC() throws Exception {
        try (InputStream jksAsStream = getClass().getResourceAsStream("/generated/intermediateCA.jks");
             InputStream cerAsStream = getClass().getResourceAsStream("/generated/intermediateCA.cer")) {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(jksAsStream, CertificateValidationTest.DEFAULT_PASSWORD.toCharArray());
            X509Certificate certificate = (X509Certificate) keyStore.getCertificate("intermediateCA");
            String expected = CharStreams.toString(new InputStreamReader(cerAsStream, Charsets.UTF_8));
            String actual = Utils.convertToPemFormat(certificate);
            assertEquals(expected.replaceAll(System.lineSeparator(), ""), actual.replaceAll(System.lineSeparator(), ""));
        }
    }
}
