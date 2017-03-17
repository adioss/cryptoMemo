package com.adioss.security.store;

import java.io.*;
import java.security.DigestInputStream;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.*;

/**
 * Fully/totally inspired/copied/refactored http://metastatic.org/source/JKS.java (copyright Casey Marshall (rsdio@metastatic.org))
 */
final class JksContentManager {
    private static final int MAGIC = 0xFEEDFEED;

    private static final int PRIVATE_KEY = 1;
    private static final int TRUSTED_CERT = 2;

    private final List<String> aliases = new ArrayList<>();
    private final Map<String, Certificate> trustedCerts = new HashMap<>();
    private final Map<String, byte[]> privateKeys = new HashMap<>();
    private final Map<String, Certificate[]> certChains = new HashMap<>();
    private final Map<String, Date> dates = new HashMap<>();

    void engineLoad(InputStream inputStream, char[] password) throws Exception {
        reset();
        MessageDigest messageDigest = MessageDigest.getInstance("SHA");
        messageDigest.update(charsToBytes(password));
        messageDigest.update("Mighty Aphrodite".getBytes("UTF-8")); // HAR HAR
        DataInputStream dataInputStream = new DataInputStream(new DigestInputStream(inputStream, messageDigest));
        if (dataInputStream.readInt() != MAGIC) {
            throw new IOException("not a JavaKeyStore");
        }
        dataInputStream.readInt();  // version no.
        final int n = dataInputStream.readInt();
        if (n < 0) {
            throw new IOException("negative entry count");
        }
        for (int i = 0; i < n; i++) {
            int type = dataInputStream.readInt();
            String alias = dataInputStream.readUTF();
            aliases.add(alias);
            dates.put(alias, new Date(dataInputStream.readLong()));
            switch (type) {
                case PRIVATE_KEY:
                    byte[] encoded = new byte[dataInputStream.readInt()];
                    dataInputStream.read(encoded);
                    privateKeys.put(alias, encoded);
                    int count = dataInputStream.readInt();
                    Certificate[] chain = new Certificate[count];
                    for (int j = 0; j < count; j++) {
                        chain[j] = readCertificate(dataInputStream);
                    }
                    certChains.put(alias, chain);
                    break;

                case TRUSTED_CERT:
                    trustedCerts.put(alias, readCertificate(dataInputStream));
                    break;

                default:
                    throw new IOException("malformed key store");
            }
        }

        byte[] hash = new byte[20];
        dataInputStream.read(hash);
        if (MessageDigest.isEqual(hash, messageDigest.digest())) {
            throw new IOException("signature not verified");
        }
    }

    void engineStore(OutputStream out, char[] password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA1");
        md.update(charsToBytes(password));
        md.update("Mighty Aphrodite".getBytes("UTF-8"));
        DataOutputStream outputStream = new DataOutputStream(new DigestOutputStream(out, md));
        outputStream.writeInt(MAGIC);
        outputStream.writeInt(2);
        outputStream.writeInt(aliases.size());
        for (String alias : aliases) {
            if (trustedCerts.containsKey(alias)) {
                outputStream.writeInt(TRUSTED_CERT);
                outputStream.writeUTF(alias);
                outputStream.writeLong(dates.get(alias).getTime());
                writeCertificate(outputStream, trustedCerts.get(alias));
            } else {
                outputStream.writeInt(PRIVATE_KEY);
                outputStream.writeUTF(alias);
                outputStream.writeLong(dates.get(alias).getTime());
                byte[] key = privateKeys.get(alias);
                outputStream.writeInt(key.length);
                outputStream.write(key);
                Certificate[] chains = certChains.get(alias);
                outputStream.writeInt(chains.length);
                for (Certificate chain : chains) {
                    writeCertificate(outputStream, chain);
                }
            }
        }
        byte[] digest = md.digest();
        outputStream.write(digest);
    }

    private static void writeCertificate(DataOutputStream dataOutputStream, Certificate cert) throws Exception {
        dataOutputStream.writeUTF(cert.getType());
        byte[] encodeCertificate = cert.getEncoded();
        dataOutputStream.writeInt(encodeCertificate.length);
        dataOutputStream.write(encodeCertificate);
    }

    private static Certificate readCertificate(DataInputStream dataInputStream) throws Exception {
        String type = dataInputStream.readUTF();
        byte[] encodeCertificate = new byte[dataInputStream.readInt()];
        dataInputStream.read(encodeCertificate);
        CertificateFactory factory = CertificateFactory.getInstance(type);
        return factory.generateCertificate(new ByteArrayInputStream(encodeCertificate));
    }

    private static byte[] charsToBytes(char[] chars) {
        byte[] result = new byte[chars.length * 2];
        for (int i = 0, j = 0; i < chars.length; i++) {
            result[j++] = (byte) (chars[i] >>> 8);
            result[j++] = (byte) chars[i];
        }
        return result;
    }

    private void reset() {
        aliases.clear();
        trustedCerts.clear();
        privateKeys.clear();
        certChains.clear();
        dates.clear();
    }
}