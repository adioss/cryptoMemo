package com.adioss.security.tls;

import java.io.*;
import java.net.InetAddress;
import javax.net.ssl.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.adioss.security.Utils;

import static com.adioss.security.tls.BasicTlsServer.SERVER_PORT;

class BasicTlsClient {
    private static final Logger LOG = LoggerFactory.getLogger(BasicTlsClient.class);

    private StringBuilder data;
    private SSLSocket socket;

    BasicTlsClient(String trustStore) {
        try {
            SSLContext sslContext = SslContextUtils.createSSLContext(null, null, trustStore);
            socket = (SSLSocket) sslContext.getSocketFactory().createSocket(InetAddress.getLocalHost(), SERVER_PORT);
            LOG.info("Client socket created");
        } catch (Exception e) {
            LOG.error("Impossible to create client socket.", e);
            throw new RuntimeException(e);
        }
    }

    BasicTlsClient start() throws IOException {
        LOG.info("Session started.");
        data = new StringBuilder();
        try (OutputStream outputStream = socket.getOutputStream(); InputStream inputStream = socket.getInputStream()) {
            // right some data
            outputStream.write(Utils.toByteArray("end char: "));
            // stop char
            outputStream.write('!');
            // read data from server
            int ch;
            while ((ch = inputStream.read()) != '!') {
                data.append((char) ch);
            }
            data.append((char) ch);
        }
        LOG.info("Session closed.");
        return this;
    }

    BasicTlsClient stop() throws IOException {
        socket.close();
        return this;
    }

    String getData() {
        return data.toString();
    }
}
