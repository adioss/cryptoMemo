package com.adioss.security.tls;

import java.io.*;
import java.util.concurrent.*;
import javax.net.ssl.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.adioss.security.Utils;

class BasicTlsServer {
    private static final Logger LOG = LoggerFactory.getLogger(BasicTlsServer.class);
    static final int SERVER_PORT = 12345;

    private final ExecutorService executorService = Executors.newFixedThreadPool(1);

    private SSLSocket socket;
    private SSLServerSocket sslServerSocket;

    BasicTlsServer(String keyStore, char[] keyStorePassword) {
        try {
            // To have a default one, can be provided as command line or
            // System.setProperty("javax.net.ssl.keyStore", keyStore);
            // System.setProperty("javax.net.ssl.keyStorePassword", keyStorePassword);
            // be here we manually create an SSLContext
            SSLContext sslContext = SslContextUtils.createSSLContext(keyStore, keyStorePassword, null);
            SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();
            sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(SERVER_PORT);
            LOG.info("Server factory created");
        } catch (Exception e) {
            LOG.error("Impossible to create server factory.", e);
            throw new RuntimeException(e);
        }
    }

    BasicTlsServer start() throws IOException {
        LOG.info("Start session.");
        executorService.submit(() -> {
            LOG.info("Session started.");
            try {
                socket = (SSLSocket) sslServerSocket.accept();
            } catch (IOException e) {
                LOG.error("Error during Server socket creation", e);
                throw new RuntimeException(e);
            }
            try (InputStream inputStream = socket.getInputStream(); OutputStream outputStream = socket.getOutputStream()) {
                // write data
                outputStream.write(Utils.toByteArray("Write some data until "));
                int ch;
                while ((ch = inputStream.read()) != '!') {
                    outputStream.write(ch);
                }
                outputStream.write('!');
            } catch (IOException e) {
                LOG.error("Error during Server session", e);
                throw new RuntimeException(e);
            }
            LOG.info("Session closed.");
        });
        return this;
    }

    BasicTlsServer stop() throws IOException {
        socket.close();
        return this;
    }
}
