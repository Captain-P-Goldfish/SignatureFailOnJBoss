package de.gold;

import de.gold.certificates.CertificateCreator;
import de.gold.certificates.DistinguishedName;
import org.apache.log4j.Logger;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.ejb.Stateless;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.xml.crypto.*;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.*;
import java.security.cert.*;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

/**
 * author: Pascal Knueppel created at: 16.07.2015
 */
@Stateless
@Path("signature")
public class SignatureRessource {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final Logger logger = Logger.getLogger(SignatureRessource.class);
    private static final String xmlEncoding = "ISO-8859-15";
    private static final String xmlString = "<signme><data>some data to sign</data></signme>";
    private static       Document sourceDoc;
    private static final KeyStore signingKeystore = generateKeyStore();


    @GET
    @Path("create")
    @Produces({"application/xml"})
    public String createEnvelopedSignature()
            throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        X509Certificate verificationCertificate =
                                   (X509Certificate) signingKeystore.getCertificate(SignatureApplication.keyStoreAlias);
        PrivateKey signingKey = (PrivateKey) signingKeystore.getKey(SignatureApplication.keyStoreAlias,
                                                                   SignatureApplication.keyStorePassword.toCharArray());
        sourceDoc = retrieveXml(xmlString);
        if (sourceDoc == null) {
            throw new RuntimeException("signature cannot be provided if document is null");
        }

        String messageDigestAlgorithm = "http://www.w3.org/2000/09/xmldsig#sha1";
        String signingAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

        Document document = cloneDocument(sourceDoc);
        document.normalizeDocument();
        String providerName = System.getProperty("jsr105Provider", "org.jcp.xml.dsig.internal.dom.XMLDSigRI");

        try {
            if (logger.isDebugEnabled()) {
                logger.debug("starting to create enveloped signature...");
                logger.debug("messageDigestAlgorithm: " + messageDigestAlgorithm);
                logger.debug("signatureAlgorithm: " + signingAlgorithm);
            }
            XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM",
                    (Provider) Class.forName(providerName).newInstance());

            Reference ref = fac.newReference(
                    "",
                    fac.newDigestMethod(messageDigestAlgorithm, null),
                    Collections.singletonList(fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)),
                    null,
                    null
            );

            SignedInfo signedInfo = fac.newSignedInfo(
                    fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null),
                    fac.newSignatureMethod(signingAlgorithm, null),
                    Collections.singletonList(ref));

            KeyInfoFactory kif = fac.getKeyInfoFactory();

            X509Data x509d = kif.newX509Data(Collections.singletonList(verificationCertificate));
            javax.xml.crypto.dsig.keyinfo.KeyInfo keyInfo = kif.newKeyInfo(Collections.singletonList(x509d));

            DOMSignContext dsc = new DOMSignContext(signingKey, document.getDocumentElement());

            javax.xml.crypto.dsig.XMLSignature signature = fac.newXMLSignature(signedInfo, keyInfo);
            signature.sign(dsc);
            if (logger.isDebugEnabled()) {
                logger.debug("signature creation was successful.");
                logger.debug(documentToString(document));
            }
            sourceDoc = document;
            return documentToString(document);

        } catch (IllegalAccessException | ClassNotFoundException | InvalidAlgorithmParameterException |
                XMLSignatureException | InstantiationException | NoSuchAlgorithmException | MarshalException e) {
            throw new RuntimeException("signature could not be provided", e);
        }
    }

    @GET
    @Path("verify")
    @Produces({"text/plain"})
    public boolean verifySignature() {
        if (sourceDoc == null) {
            throw new RuntimeException("signature cannot be verified if document is null.");
        }
        sourceDoc.normalizeDocument();
        try {
            if (logger.isDebugEnabled()) {
                logger.debug("starting verification of signature...");
            }
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);

            NodeList nl = sourceDoc.getElementsByTagNameNS(javax.xml.crypto.dsig.XMLSignature.XMLNS, "Signature");
            if (nl.getLength() == 0) {
                throw new RuntimeException("Cannot find Signature element.\n " +
                        "Remember that the successful verification of the signature will remove the signature from" +
                        " the document!");
            }
            String providerName = System.getProperty("jsr105Provider", "org.jcp.xml.dsig.internal.dom.XMLDSigRI");

            XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM",
                    (Provider) Class.forName(providerName).newInstance());
            DOMValidateContext valContext = new DOMValidateContext(new KeyValueKeySelector(), nl.item(0));

            javax.xml.crypto.dsig.XMLSignature signature = fac.unmarshalXMLSignature(valContext);
            boolean coreValidity = signature.validate(valContext);

//            if (removeSignatureFromDocument) {
//                if (logger.isDebugEnabled()) {
//                    logger.debug("remove signature from document.");
//                }
//                Node signatureElement = nl.item(0);
//                if (signatureElement.getParentNode() != null) {
//                    signatureElement.getParentNode().removeChild(signatureElement);
//                } else {
//                    throw new RuntimeException("signature node cannot be removed for it is representing the root " +
//                            "node.");
//                }
//                if (logger.isDebugEnabled()) {
//                    logger.debug("signature was remove from document.");
//                }
//            }
            if (!coreValidity && logger.isDebugEnabled()) {
                // optional. Java allows me to get more information
                // on failed verification
                boolean sv = signature.getSignatureValue().validate(valContext);
                logger.debug("verifySignature: verified by value! signature validation status=" + sv);

                // Check the validation status of each Reference
                Iterator i = signature.getSignedInfo().getReferences().iterator();
                for (int j = 0; i.hasNext(); j++)
                {
                    boolean refValid = ((Reference) i.next()).validate(valContext);
                    logger.debug("verifySignature: Reference (" + j + ") validation status: " + refValid);
                }
            }

            if (coreValidity) {
                logger.debug("document signature was verified successfully.");
                logger.debug(documentToString(sourceDoc));

            } else {
                logger.error("document signature could not be verified.");
            }
            return coreValidity;
        } catch (XMLSignatureException | MarshalException | InstantiationException |
                IllegalAccessException | ClassNotFoundException e) {
            throw new RuntimeException("document signature could not be verified", e);
        }
    }

    private static class KeyValueKeySelector extends KeySelector {

        public KeySelectorResult select(KeyInfo keyInfo,
                                        Purpose purpose, AlgorithmMethod method,
                                        XMLCryptoContext context) throws KeySelectorException {

            if (keyInfo == null) {
                throw new KeySelectorException("Null KeyInfo object!");
            }
            SignatureMethod sm = (SignatureMethod) method;
            List list = keyInfo.getContent();

            for (int i = 0; i < list.size(); i++) {
                XMLStructure xmlStructure = (XMLStructure) list.get(i);
                if (xmlStructure instanceof X509Data) {
                    X509Data x509 = (X509Data) xmlStructure;
                    for (Object content : x509.getContent()) {
                        if (content instanceof X509Certificate) {
                            PublicKey pk = ((X509Certificate) content).getPublicKey();
                            return new SimpleKeySelectorResult(pk);
                        }
                    }
                    return null;
                }

                if (xmlStructure instanceof X509Certificate) {
                    PublicKey pk = ((X509Certificate) xmlStructure).getPublicKey();
                    return new SimpleKeySelectorResult(pk);
                }

                PublicKey pk = ((X509Certificate) xmlStructure).getPublicKey();
                return new SimpleKeySelectorResult(pk);

            }
            throw new KeySelectorException("No KeyValue element found!");
        }
    }

    private static class SimpleKeySelectorResult implements KeySelectorResult {
        private PublicKey pk;

        SimpleKeySelectorResult(PublicKey pk) {
            this.pk = pk;
        }

        public Key getKey() {
            return pk;
        }
    }

    public static Document retrieveXml(String doc) {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            DocumentBuilder documentBuilder = dbf.newDocumentBuilder();
            Reader reader = new StringReader(doc);
            InputSource is = new InputSource(reader);
            is.setEncoding(xmlEncoding);
            Document document = documentBuilder.parse(is);

            if (logger.isDebugEnabled()) {
                logger.debug("retrieveXml: doc=" + doc
                        + "; document=" + document + "; encoding=" + document.getXmlEncoding());
            }

            return document;
        } catch (ParserConfigurationException | SAXException | IOException e) {
            throw new IllegalStateException("Das DOM-Modell konnte nicht aus dem übergebenen String erzeugt werden.",
                    e);
        }
    }

    public static Document cloneDocument(Document doc) {
        try {
            TransformerFactory tfactory = TransformerFactory.newInstance();
            Transformer transformer   = tfactory.newTransformer();
            transformer.setOutputProperty(OutputKeys.ENCODING, xmlEncoding);
            DOMSource source = new DOMSource(doc);
            DOMResult result = new DOMResult();
            transformer.transform(source, result);
            Document clone = (Document) result.getNode();

            if (logger.isDebugEnabled()) {
                logger.debug("cloneDocument: dom cloned! source=" + doc + "; clone=" + clone + "; clone encoding=" +
                        clone.getXmlEncoding());
            }

            return clone;
        } catch (TransformerException e) {
            throw new IllegalStateException("Klonen des DOM-Modells ist fehlgeschlagen", e);
        }
    }

    public static String documentToString(Document document) {
        try {
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer = tf.newTransformer();
            transformer.setOutputProperty(OutputKeys.ENCODING, xmlEncoding);
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
            transformer.setOutputProperty(OutputKeys.METHOD, "xml");
            transformer.setOutputProperty(OutputKeys.INDENT, "no");
            StringWriter sw = new StringWriter();
            transformer.transform(new DOMSource(document), new StreamResult(sw));
            return sw.toString();
        } catch (TransformerException e) {
            throw new IllegalStateException("Das DOM-Modell konnte nicht in einen String übersetzt werden.", e);
        }
    }

    public static KeyStore generateKeyStore() {
        KeyStore keyStore;
        logger.info("alias = " + SignatureApplication.keyStoreAlias);
        try {
            keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            KeyPair keyPair = generateKey();
            CertificateCreator certificateCreator = new CertificateCreator();
            DistinguishedName dn = new DistinguishedName("signature service", null, null, null, null, null);
            X509Certificate certificate = certificateCreator.createX509SelfSignedCertificate(
                    keyPair,
                    dn,
                    new Date(),
                    new Date(System.currentTimeMillis() + 3600L * 24 * 365)
            );
            java.security.cert.Certificate[] certChain = {certificate};
            PrivateKey privateKey = keyPair.getPrivate();
            keyStore.setEntry(SignatureApplication.keyStoreAlias,
                    new KeyStore.PrivateKeyEntry(privateKey, certChain),
                    new KeyStore.PasswordProtection(SignatureApplication.keyStorePassword.toCharArray()));
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            throw new RuntimeException(e);
        }
        logger.info("keyStore = " + keyStore);
        return keyStore;
    }

    public static KeyPair generateKey () {
        KeyGenerationParameters keyGenerationParameters = new KeyGenerationParameters(new SecureRandom(), 2048);
        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA", SignatureApplication.defaultProvider);
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException("rsa-key-pair could not be created", e);
        }
        keyPairGenerator.initialize(keyGenerationParameters.getStrength(), keyGenerationParameters.getRandom());
        return keyPairGenerator.generateKeyPair();
    }
}
