package com.adioss.security.tls;

import java.io.*;
import java.nio.file.Paths;
import java.util.concurrent.*;
import javax.net.ssl.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.adioss.security.Utils;

public class BasicTlsServer {
    private static final Logger LOG = LoggerFactory.getLogger(BasicTlsServer.class);
    static final int SERVER_PORT = 12345;

    private final ExecutorService executorService = Executors.newFixedThreadPool(1);
    private final String keyStore;
    private final String keyStorePassword;
    private SSLSocket socket;
    private SSLServerSocket sslServerSocket;

    BasicTlsServer() {
        this(null, null);
    }

    BasicTlsServer(String keyStore, String keyStorePassword) {
        this.keyStore = keyStore;
        this.keyStorePassword = keyStorePassword;
    }

    BasicTlsServer init() throws IOException {
        // Init system properties
        System.setProperty("javax.net.ssl.keyStore", keyStore);
        System.setProperty("javax.net.ssl.keyStorePassword", keyStorePassword);
        // Create socket
        SSLServerSocketFactory sslServerSocketFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
        LOG.info("Create server factory");
        sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(SERVER_PORT);
        return this;
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

    public static void main(String... args) throws Exception {
        String keyStore = Paths.get(BasicTlsServer.class.getResource("/generated/signedBySubIntermediate.jks").toURI()).toString();
        new BasicTlsServer(keyStore, "changeit").init().start();
    }
}
