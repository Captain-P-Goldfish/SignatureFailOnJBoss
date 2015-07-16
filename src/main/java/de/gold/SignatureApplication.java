package de.gold;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

/**
 * author: Pascal Knueppel created at: 16.07.2015
 */
@ApplicationPath("service")
public class SignatureApplication extends Application {

    public static final String defaultProvider = "BC";
    public static final String keyStoreAlias = "signatureAlias";
    public static final String keyStorePassword = "signaturePassword";
}
