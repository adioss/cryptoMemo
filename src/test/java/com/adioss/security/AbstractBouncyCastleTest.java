package com.adioss.security;

import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.Before;

/**
 * Add/remove bouncy castle provider before/after tests
 */
public class AbstractBouncyCastleTest {

    private String name;

    @Before
    public void setUp() throws Exception {
        BouncyCastleProvider provider = new BouncyCastleProvider();
        name = provider.getName();
        Security.addProvider(provider);
    }

    @After
    public void tearDown() throws Exception {
        Security.removeProvider(name);
    }
}
