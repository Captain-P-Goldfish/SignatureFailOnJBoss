package de.gold;


import org.junit.Assert;
import org.junit.Test;

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;

/**
 * author: Pascal Knueppel
 * created at: 16.07.2015
 */
public class SignatureRessourceTest {

    @Test
    public void testSignatureCreationAndVerification()
            throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        SignatureRessource signatureRessource = new SignatureRessource();
        signatureRessource.createEnvelopedSignature();
        Assert.assertTrue(signatureRessource.verifySignature());
    }

}