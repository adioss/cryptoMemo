package com.adioss.security.tls;

import java.nio.file.Paths;
import org.junit.Assert;
import org.junit.Test;

public class BasicTlsServerTest {
    @Test
    public void shouldCreateClientServerTlsCommunication() throws Exception {
        // Given

        // When
        String trustStore = Paths.get(getClass().getResource("/generated/signedBySubIntermediate.truststore.jks").toURI()).toString();
        BasicTlsClient basicTlsClient = new BasicTlsClient(trustStore, "changeit").init().start().stop();
        // Then
        Assert.assertNotEquals("", basicTlsClient.getData());
    }
}
