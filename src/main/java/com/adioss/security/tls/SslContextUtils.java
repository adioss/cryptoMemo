package com.adioss.security.tls;

import java.io.*;
import java.security.KeyStore;
import java.security.SecureRandom;
import javax.net.ssl.*;

import static com.google.common.base.Strings.isNullOrEmpty;

class SslContextUtils {
    /**
     * Create an {@link SSLContext} based on a {@link KeyStore} keystore/truststore
     *
     * @param keyStorePath the absolute path to the {@link KeyStore} keystore
     * @param keyStorePassword {@link KeyStore} keyStorePassword
     * @param trustStorePath the absolute path to the {@link KeyStore} truststore
     * @return an initialized {@link SSLContext}
     */
    static SSLContext createSSLContext(String keyStorePath, char[] keyStorePassword, String trustStorePath) throws Exception {
        KeyManagerFactory keyManagerFactory = null;

        TrustManagerFactory trustManagerFactory = null;

        if (!isNullOrEmpty(keyStorePath)) {
            keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            try (FileInputStream fileInputStream = new FileInputStream(keyStorePath)) {
                KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                keyStore.load(fileInputStream, keyStorePassword);
                keyManagerFactory.init(keyStore, keyStorePassword);
            }
        }

        if (!isNullOrEmpty(trustStorePath)) {
            trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            try (FileInputStream fileInputStream = new FileInputStream(trustStorePath)) {
                KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                keyStore.load(fileInputStream, null);
                trustManagerFactory.init(keyStore);
            }
        }

        SSLContext sslContext = SSLContext.getInstance("TLS");
        TrustManager[] trustManagers = trustManagerFactory != null ? trustManagerFactory.getTrustManagers() : null;
        KeyManager[] keyManagers = keyManagerFactory != null ? keyManagerFactory.getKeyManagers() : null;
        sslContext.init(keyManagers, trustManagers, new SecureRandom());
        return sslContext;
    }
}
