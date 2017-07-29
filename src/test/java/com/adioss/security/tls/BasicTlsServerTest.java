package com.adioss.security.tls;

import java.nio.file.Paths;
import org.junit.Assert;
import org.junit.Test;

public class BasicTlsServerTest {
    private static final char[] DEFAULT_PASSWORD = "changeit".toCharArray();

    @Test
    public void shouldCreateClientServerTlsCommunication() throws Exception {
        // Given
        String keyStore = Paths.get(getClass().getResource("/generated/signedBySubIntermediate.jks").toURI()).toString();
        BasicTlsServer basicTlsServer = new BasicTlsServer(keyStore, DEFAULT_PASSWORD).start();
        // When
        String trustStore = Paths.get(getClass().getResource("/generated/truststore.jks").toURI()).toString();
        BasicTlsClient basicTlsClient = new BasicTlsClient(trustStore).start().stop();
        // Then
        String data = basicTlsClient.getData();
        Assert.assertNotEquals("", data);
    }
}
