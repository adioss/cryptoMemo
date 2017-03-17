package com.adioss.security.store;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;

public class JksPasswordBypasser {
    private JksPasswordBypasser() {
    }

    static void copyStoreToUnProtected(String keyStoreFilePath) throws Exception {
        JksContentManager jksContentManager = new JksContentManager();

        try (InputStream in = new FileInputStream(keyStoreFilePath)) {
            jksContentManager.engineLoad(in, "".toCharArray());
        }

        String outputPath = Paths.get(keyStoreFilePath).getParent() + File.separator + "result.jks";
        System.out.printf("Copy '%s' content and writing it to '%s' with empty password\n", keyStoreFilePath, outputPath);

        try (OutputStream out = new FileOutputStream(outputPath)) {
            jksContentManager.engineStore(out, "".toCharArray());
        }
        System.out.println("KeyStore with empty password created: " + outputPath);
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.out.println("Usage: java JksPasswordBypasser keyStoreFilePath");
            return;
        }
        String keyStoreFilePath = args[0];
        if (!Files.exists(Paths.get(keyStoreFilePath))) {
            System.out.println("Incorrect path to store");
            System.out.println("Usage: java JksPasswordBypasser keyStoreFilePath");
        }

        copyStoreToUnProtected(keyStoreFilePath);
    }
}
