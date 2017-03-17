package com.adioss.security.store;

import java.io.*;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.*;
import org.junit.Assert;
import org.junit.Test;

public class JksPasswordBypasserTest {

    private static final String EMPTY_PASSWORD = "";

    @Test
    public void shouldCopyStoreToUnProtected() throws Exception {
        // Given
        String path = Paths.get(getClass().getResource("/test.keystore.jks").toURI()).toString();

        // When
        JksPasswordBypasser.copyStoreToUnProtected(path);

        // Then
        Path resultPath = Paths.get(getClass().getResource("/result.jks").toURI());
        Assert.assertNotNull(resultPath);
        File file = resultPath.toFile();
        try (FileInputStream keyStoreStream = new FileInputStream(file)) {
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            keystore.load(keyStoreStream, EMPTY_PASSWORD.toCharArray());
            Enumeration enumeration = keystore.aliases();
            String alias = (String) enumeration.nextElement();
            Assert.assertEquals("my-cn", alias);
            Certificate certificate = keystore.getCertificate(alias);
            Assert.assertNotNull(certificate);
            Assert.assertNotNull(certificate.getPublicKey());
            Assert.assertFalse(enumeration.hasMoreElements());
        }
    }
}
