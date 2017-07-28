package com.adioss.security.tls;

import java.io.*;
import java.net.InetAddress;
import javax.net.ssl.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.adioss.security.Utils;

import static com.adioss.security.tls.BasicTlsServer.SERVER_PORT;

public class BasicTlsClient {
    private static final Logger LOG = LoggerFactory.getLogger(BasicTlsClient.class);

    private final String trustStore;
    private final String trustStorePassword;
    private String data = "";
    private SSLSocket socket;

    BasicTlsClient() {
        this(null, null);
    }

    BasicTlsClient(String trustStore, String trustStorePassword) {
        this.trustStore = trustStore;
        this.trustStorePassword = trustStorePassword;
    }

    BasicTlsClient init() throws IOException {
        // Init system properties
        System.setProperty("javax.net.ssl.trustStore", trustStore);
        System.setProperty("javax.net.ssl.trustStorePassword", trustStorePassword);
        // Create socket
        SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        LOG.info("Create client socket");
        socket = (SSLSocket) sslSocketFactory.createSocket(InetAddress.getLocalHost(), SERVER_PORT);
        return this;
    }

    BasicTlsClient start() throws IOException {
        LOG.info("Session started.");
        try (OutputStream outputStream = socket.getOutputStream(); InputStream inputStream = socket.getInputStream()) {
            // right some data
            outputStream.write(Utils.toByteArray("until"));
            // stop char
            outputStream.write('!');
            // read data from server
            int ch;
            while ((ch = inputStream.read()) != '!') {
                data += (char) ch;
            }
            data += (char) ch;
        }
        LOG.info("Session closed.");
        return this;
    }

    BasicTlsClient stop() throws IOException {
        socket.close();
        return this;
    }

    public String getData() {
        return data;
    }
}
