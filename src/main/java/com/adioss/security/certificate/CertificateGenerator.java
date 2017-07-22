package com.adioss.security.certificate;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import com.google.common.annotations.VisibleForTesting;

public class CertificateGenerator {
    private static final int VALIDITY_PERIOD = 7 * 24 * 60 * 60 * 1000; // one week
    private static final String SIGNATURE_ALGORITHM = "SHA256WithRSAEncryption";
    private static final Date START_DATE = new Date(System.currentTimeMillis() - 50000);
    private static final Date END_DATE = new Date(System.currentTimeMillis() + VALIDITY_PERIOD);

    /**
     * Generate a V1 version(ex usage is CA root) of X.509 self signed certificate
     *
     * @param keyPair used to generate certificate: public key in certificate, sign with private key (self signed)
     * @return a self signed {@link X509Certificate}
     */
    @VisibleForTesting
    static X509Certificate generateX509V1Certificate(KeyPair keyPair) throws Exception {
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        X509v1CertificateBuilder x509v1CertificateBuilder = new X509v1CertificateBuilder(new X500Name("CN=Test Certificate"), serial, START_DATE, END_DATE,
                                                                                         new X500Name("CN=Fake Issuer DN"),
                                                                                         SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()));
        ContentSigner contentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(keyPair.getPrivate());

        X509CertificateHolder x509CertificateHolder = x509v1CertificateBuilder.build(contentSigner);
        return new JcaX509CertificateConverter().getCertificate(x509CertificateHolder);
    }

    /**
     * Same source code as {@code generateX509V1Certificate} but with a V3 of X.509: root CA certificate (V3 version of X.509 self signed certificate)
     */
    public static X509Certificate generateRootCert(KeyPair keyPair, String subjectValue) throws Exception {
        X500Name x500Name = new X500Name(subjectValue);
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(x500Name, serial, START_DATE, END_DATE, x500Name,
                                                                                         SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()));
        // can sign only next level. Critical: true
        x509v3CertificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
        // can sign certificate or encrypt other keys
        x509v3CertificateBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign));

        ContentSigner contentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(keyPair.getPrivate());

        // generate certificate
        X509CertificateHolder x509CertificateHolder = x509v3CertificateBuilder.build(contentSigner);
        return new JcaX509CertificateConverter().getCertificate(x509CertificateHolder);
    }

    /**
     * Create an intermediate CA, sign by root CA, used to sign other certificates
     */
    public static X509Certificate generateIntermediateCA(KeyPair keyPair, KeyPair caRootKeyPair, X509Certificate caCert, String subjectValue) throws Exception {
        ContentSigner contentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(caRootKeyPair.getPrivate());

        X500Name subject = new X500Name(subjectValue);
        X500Name issuer = new X500Name(caCert.getSubjectDN().getName());

        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
        PKCS10CertificationRequestBuilder certificationRequestBuilder = new PKCS10CertificationRequestBuilder(subject, subjectPublicKeyInfo);
        PKCS10CertificationRequest request = certificationRequestBuilder.build(contentSigner);

        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        X500Name subject1 = request.toASN1Structure().getCertificationRequestInfo().getSubject();
        X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(issuer, serial, START_DATE, END_DATE, //
                                                                                         subject1, request.getSubjectPublicKeyInfo());
        // can sign any size path of next level. Critical: true
        x509v3CertificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(Integer.MAX_VALUE));
        // can sign certificate or encrypt other keys. Critical: true
        x509v3CertificateBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign));
        // add issuer subjectKey identifier. Critical: false
        AuthorityKeyIdentifier authorityKeyIdentifier = new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(caCert.getPublicKey());
        x509v3CertificateBuilder.addExtension(Extension.authorityKeyIdentifier, false, authorityKeyIdentifier);
        // add subjectKey identifier. Critical: false
        SubjectKeyIdentifier subjectKeyIdentifier = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keyPair.getPublic());
        x509v3CertificateBuilder.addExtension(Extension.subjectKeyIdentifier, false, subjectKeyIdentifier);
        // put a DNS SAN. Critical: false
        GeneralNames generalNames = new GeneralNames(new GeneralName[]{new GeneralName(GeneralName.dNSName, subjectValue + ".intermediate.ca")});
        x509v3CertificateBuilder.addExtension(Extension.subjectAlternativeName, false, generalNames);

        // generate certificate
        X509CertificateHolder x509CertificateHolder = x509v3CertificateBuilder.build(contentSigner);
        return new JcaX509CertificateConverter().getCertificate(x509CertificateHolder);
    }

    /**
     * Create basic certificate signed by intermediate CA
     */
    @VisibleForTesting
    public static X509Certificate generateEndEntityCert(KeyPair keyPair, KeyPair intermediateCaKeyPair, X509Certificate intermediateCaKeyCertificate,
                                                        String subjectValue) throws Exception {
        ContentSigner contentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(intermediateCaKeyPair.getPrivate());

        X500Name subject = new X500Name(subjectValue);
        X500Name issuer = new X500Name(intermediateCaKeyCertificate.getSubjectDN().getName());

        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
        PKCS10CertificationRequestBuilder certificationRequestBuilder = new PKCS10CertificationRequestBuilder(subject, subjectPublicKeyInfo);
        PKCS10CertificationRequest request = certificationRequestBuilder.build(contentSigner);

        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        X500Name subject1 = request.toASN1Structure().getCertificationRequestInfo().getSubject();
        X509v3CertificateBuilder x509v3CertificateBuilder = new X509v3CertificateBuilder(issuer, serial, START_DATE, END_DATE, //
                                                                                         subject1, request.getSubjectPublicKeyInfo());
        // not a CA
        x509v3CertificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        // server auth. Critical: true
        x509v3CertificateBuilder.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
        //  public key is used for key transport. Critical: true
        x509v3CertificateBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        // add issuer subjectKey identifier. Critical: false
        AuthorityKeyIdentifier authorityKeyIdentifier = new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(intermediateCaKeyCertificate.getPublicKey());
        x509v3CertificateBuilder.addExtension(Extension.authorityKeyIdentifier, false, authorityKeyIdentifier);
        // add subjectKey identifier. Critical: false
        SubjectKeyIdentifier subjectKeyIdentifier = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(keyPair.getPublic());
        x509v3CertificateBuilder.addExtension(Extension.subjectKeyIdentifier, false, subjectKeyIdentifier);
        // put a DNS SAN
        GeneralNames generalNames = new GeneralNames(new GeneralName[]{new GeneralName(GeneralName.dNSName, subjectValue + ".end.certificate.ca")});
        x509v3CertificateBuilder.addExtension(Extension.subjectAlternativeName, false, generalNames);

        // generate certificate
        X509CertificateHolder x509CertificateHolder = x509v3CertificateBuilder.build(contentSigner);
        return new JcaX509CertificateConverter().getCertificate(x509CertificateHolder);
    }

    private CertificateGenerator() {
    }
}
