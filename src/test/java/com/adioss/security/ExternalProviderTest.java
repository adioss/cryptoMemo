package com.adioss.security;

import org.junit.Test;

public class ExternalProviderTest extends AbstractBouncyCastleTest {
    @Test
    public void shouldTestExternalProviderInstallation() throws Exception {
        ExternalProvider.testExternalProviderInstallation();
    }

    @Test
    public void shouldTestProviderPriority() throws Exception {
        ExternalProvider.testProviderPriority();
    }
}
