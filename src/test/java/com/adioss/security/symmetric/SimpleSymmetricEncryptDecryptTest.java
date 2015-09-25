package com.adioss.security.symmetric;

import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;

public class SimpleSymmetricEncryptDecryptTest {
    private static final String CLEAR_FILE_NAME = "/inputFile.txt";
    private static final String ENCRYPTED_FILE_NAME = "/encryptedFile.txt";
    private static final String TEMP_FILE_NAME = "/outputFile.txt";
    // key size must be 16 or 128 for AES
    private static final String KEY = "Mary has one cat";
    public static final String KEY_ALGORITHM = "AES";
    public static final String CIPHER_TRANSFORMATION_ALGORITHM = "AES";

    @Rule
    public TemporaryFolder testFolder = new TemporaryFolder();

    @Test
    public void testEncrypt() throws Exception {
        // Given
        File inputFile = loadFile(CLEAR_FILE_NAME);
        File outputFile = testFolder.newFile(TEMP_FILE_NAME);
        SimpleSymmetricEncryptDecrypt encryptDecrypt = new SimpleSymmetricEncryptDecrypt();

        // When
        encryptDecrypt.encrypt(inputFile, outputFile, KEY.getBytes(), KEY_ALGORITHM, CIPHER_TRANSFORMATION_ALGORITHM);

        // Then
        Assert.assertEquals(fileToString(outputFile), fileToString(loadFile(ENCRYPTED_FILE_NAME)));
    }

    @Test
    public void testDecrypt() throws Exception {
        // Given
        File inputFile = loadFile(ENCRYPTED_FILE_NAME);
        File outputFile = testFolder.newFile(TEMP_FILE_NAME);
        SimpleSymmetricEncryptDecrypt encryptDecrypt = new SimpleSymmetricEncryptDecrypt();

        // When
        encryptDecrypt.decrypt(inputFile, outputFile, KEY.getBytes(), KEY_ALGORITHM, CIPHER_TRANSFORMATION_ALGORITHM);

        // Then
        Assert.assertEquals(fileToString(outputFile), fileToString(loadFile(CLEAR_FILE_NAME)));
    }

    private String fileToString(File outputFile) throws IOException {
        return new String(Files.readAllBytes(Paths.get(outputFile.getPath())));
    }

    private File loadFile(String fileName) throws IOException, URISyntaxException {
        URL resourceUrl = getClass().getResource(fileName);
        return new File(resourceUrl.toURI());
    }
}