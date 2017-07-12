package com.adioss.security.certificate;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

class CRLGenerator {
    private static final String SIGNATURE_ALGORITHM = "SHA256WithRSAEncryption";

    /**
     * Create a {@link X509CRL}
     *
     * @param issuerCertificate the certificate of the issuer (a CA that will create a CRL of revoked certificate)
     * @param issuerKeyPair the keypair of the issuer, used the sign generated CRL
     * @param userCertificateSerials list of certificate serials to revoke
     */
    static X509CRL createCRL(X509Certificate issuerCertificate, KeyPair issuerKeyPair, BigInteger... userCertificateSerials) throws Exception {
        Date now = new Date();
        ContentSigner contentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(issuerKeyPair.getPrivate());
        X500Name issuer = new X500Name(issuerCertificate.getSubjectDN().getName());
        X509v2CRLBuilder crlGen = new X509v2CRLBuilder(issuer, now);
        crlGen.setNextUpdate(new Date(now.getTime() + 100000));
        crlGen.addExtension(Extension.authorityKeyIdentifier, false, new JcaX509ExtensionUtils().createAuthorityKeyIdentifier((issuerKeyPair.getPublic())));
        // increment
        crlGen.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(1)));

        // add CRL entries
        for (BigInteger userCertificateSerial : userCertificateSerials) {
            // privilege withdrawn on certificate. Applied now
            crlGen.addCRLEntry(userCertificateSerial, now, CRLReason.privilegeWithdrawn);
        }

        X509CRLHolder crlHolder = crlGen.build(contentSigner);
        return new JcaX509CRLConverter().getCRL(crlHolder);
    }

    private CRLGenerator() {
    }
}
