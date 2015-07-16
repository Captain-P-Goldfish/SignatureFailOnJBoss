package de.gold.certificates;

import de.gold.SignatureApplication;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * author: Pascal Knueppel
 * created at: 30.03.2015
 *
 */
public class CertificateCreator {

    private Logger logger = Logger.getLogger(CertificateCreator.class);

    static {
        Provider provider = Security.getProvider(SignatureApplication.defaultProvider);
        if (provider == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public CertificateCreator() {}


    /**
     * creates a self signed certificate
     * @param keyPair the keypair from which a self signed certificate should be generated
     * @param issuerDnText the distinguished name of the issuer (also subject)
     * @param startDate
     * @param expiryDate .
     * @return a X509Certificate v3
     * @throws Exception
     */
    public X509Certificate createX509SelfSignedCertificate(KeyPair keyPair, DistinguishedName issuerDnText,
                                                           Date startDate, Date expiryDate) {
        try {
            return createSignedX509Certificate(issuerDnText, issuerDnText, startDate, expiryDate, keyPair.getPrivate(),
                                                keyPair.getPublic());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    /**
     * creates a signed certificate
     * @param subjectDNText Die Antragssteller DN-
     * @param issuerDNText
     * @param startDate
     * @param expiryDate
     * @param signerPrivateKey
     * @param subjectPublicKey
     * @return
     * @throws Exception
     */
    public X509Certificate createSignedX509Certificate(DistinguishedName subjectDNText,
                                                       DistinguishedName issuerDNText,
                                                       Date startDate,
                                                       Date expiryDate,
                                                       PrivateKey signerPrivateKey, PublicKey subjectPublicKey) {
        if (logger.isDebugEnabled()) {
            logger.debug("starting creation of signed certificate");
        }
        X500Name subjectDN = new X500Name(subjectDNText.toString());
        X500Name issuerDN =  new X500Name(issuerDNText.toString());
        if (logger.isDebugEnabled()) {
            logger.debug("certificate issuer: " + issuerDNText.toString());
            logger.debug("certificate subject: " + subjectDNText.toString());
        }
        SubjectPublicKeyInfo
                subjPubKeyInfo = new SubjectPublicKeyInfo(ASN1Sequence.getInstance(subjectPublicKey.getEncoded()));
        BigInteger serialNumber = new BigInteger(130, new SecureRandom());

        X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(issuerDN, serialNumber, startDate, expiryDate,
                subjectDN, subjPubKeyInfo);
        ContentSigner contentSigner = null;
        try {
            contentSigner = new JcaContentSignerBuilder("SHA256withRSA")
                    .setProvider(SignatureApplication.defaultProvider).build(signerPrivateKey);
            X509Certificate x509Certificate = new JcaX509CertificateConverter()
                    .setProvider(SignatureApplication.defaultProvider).getCertificate(certGen.build(contentSigner));
            if (logger.isDebugEnabled()) {
                logger.debug("certificate creation was successfull.");
                logger.debug("certificate serialnumber: " + serialNumber);
                logger.debug("certificate will be valid from: " + startDate);
                logger.debug("certificate will be valid until: " + expiryDate);
            }
            return x509Certificate;
        } catch (OperatorCreationException | CertificateException e) {
            throw new RuntimeException(e);
        }
    }
}
