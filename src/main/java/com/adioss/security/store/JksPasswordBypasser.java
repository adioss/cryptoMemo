package com.adioss.security.store;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.lang.String.format;

public class JksPasswordBypasser {
    private static final Logger LOG = LoggerFactory.getLogger(JksPasswordBypasser.class);
    private static final String EMPTY_PASSWORD = "";

    static void copyStoreToUnProtected(String keyStoreFilePath) throws Exception {
        JksContentManager jksContentManager = new JksContentManager();

        try (InputStream in = new FileInputStream(keyStoreFilePath)) {
            jksContentManager.load(in, EMPTY_PASSWORD.toCharArray());
        }

        String outputPath = Paths.get(keyStoreFilePath).getParent() + File.separator + "result.jks";
        LOG.debug(format("Copy '%s' content and writing it to '%s' with empty password\n", keyStoreFilePath, outputPath));

        try (OutputStream out = new FileOutputStream(outputPath)) {
            jksContentManager.save(out, EMPTY_PASSWORD.toCharArray());
        }
        LOG.debug("KeyStore with empty password created: " + outputPath);
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            LOG.debug("Usage: java JksPasswordBypasser keyStoreFilePath");
            return;
        }
        String keyStoreFilePath = args[0];
        if (!Files.exists(Paths.get(keyStoreFilePath))) {
            LOG.debug("Incorrect path to store");
            LOG.debug("Usage: java JksPasswordBypasser keyStoreFilePath");
        }

        copyStoreToUnProtected(keyStoreFilePath);
    }

    private JksPasswordBypasser() {
    }
}
