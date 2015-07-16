package de.gold.certificates;

import org.bouncycastle.asn1.x500.X500Name;

import javax.security.auth.x500.X500Principal;

/**
 * Author: Pascal Knueppel
 * Date: 30.03.2015
 * Time: 11:18
 *
 */
public class DistinguishedName {

    /**
     * empty or null fields will not be displayed in the resulting DN.
     */

    private String commonName;              // CN
    private String countryName;             // C
    private String stateOrProvince;         // ST
    private String localityName;            // L
    private String organizationName;        // O
    private String organizationalUnitName;  // OU
    private String domainComponent;         // DC
    private String streetAddress;           // STREET
    private String email;                   // E



    public DistinguishedName (String commonName, String countryName, String stateOrProvince, String localityName,
                              String organizationName, String organizationalUnitName) {
        this.commonName = commonName;
        if (countryName != null) {
            assert countryName.length() == 2;
        }
        this.countryName = countryName;
        this.stateOrProvince = stateOrProvince;
        this.localityName = localityName;
        this.organizationName = organizationName;
        this.organizationalUnitName = organizationalUnitName;
    }

    public DistinguishedName (String commonName, String countryName, String stateOrProvince, String localityName,
                              String organizationName, String organizationalUnitName, String domainComponent,
                              String streetAddress, String email) {
        this.commonName = commonName;
        assert countryName != null && countryName.length() == 2;
        this.countryName = countryName;
        this.stateOrProvince = stateOrProvince;
        this.localityName = localityName;
        this.organizationName = organizationName;
        this.organizationalUnitName = organizationalUnitName;
        this.domainComponent = domainComponent;
        this.streetAddress = streetAddress;
        this.email = email;
    }

    public DistinguishedName (String completeDN) {
        String[] dnParts = completeDN.split(",");
        for (String dnPart: dnParts) {
            dnPart = dnPart.trim();
            if (dnPart.toUpperCase().startsWith("CN=")) {
                commonName = dnPart.replaceFirst("CN=", "").trim();
            } else if (dnPart.toUpperCase().startsWith("OU=")) {
                organizationalUnitName = dnPart.replaceFirst("OU=", "").trim();
            } else if (dnPart.toUpperCase().startsWith("O=")) {
                organizationName = dnPart.replaceFirst("O=", "").trim();
            } else if (dnPart.toUpperCase().startsWith("L=")) {
                localityName = dnPart.replaceFirst("L=", "").trim();
            } else if (dnPart.toUpperCase().startsWith("C=")) {
                countryName = dnPart.replaceFirst("C=", "").trim();
            } else if (dnPart.toUpperCase().startsWith("ST=")) {
                stateOrProvince = dnPart.replaceFirst("ST=", "").trim();
            } else if (dnPart.toUpperCase().startsWith("DC=")) {
                domainComponent = dnPart.replaceFirst("DC=", "").trim();
            } else if (dnPart.toUpperCase().startsWith("STREET=")) {
                streetAddress = dnPart.replaceFirst("STREET=", "").trim();
            } else if (dnPart.toUpperCase().startsWith("E=")) {
                email = dnPart.replaceFirst("E=", "").trim();
            } else if (dnPart.toUpperCase().startsWith("EMAILADDRESS=")) {
                email = dnPart.replaceFirst("EMAILADDRESS=", "").trim();
            }
        }

    }

    public String getCountryName () {
        if (countryName == null || countryName.trim().length() == 0) {
            return "";
        }
        return "C=" + countryName;
    }

    public String getCommonName () {
        if (commonName == null || commonName.trim().length() == 0) {
            return "";
        }
        return "CN=" + commonName;
    }

    public String getStateOrProvince () {
        if (stateOrProvince == null || stateOrProvince.trim().length() == 0) {
            return "";
        }
        return "ST=" + stateOrProvince;
    }

    public String getLocalityName () {
        if (localityName == null || localityName.trim().length() == 0) {
            return "";
        }
        return "L=" + localityName;
    }

    public String getOrganizationName () {
        if (organizationName == null || organizationName.trim().length() == 0) {
            return "";
        }
        return "O=" + organizationName;
    }

    public String getOrganizationalUnitName () {
        if (organizationalUnitName == null || organizationalUnitName.trim().length() == 0) {
            return "";
        }
        return "OU=" + organizationalUnitName;
    }

    public String getDomainComponent () {
        if (domainComponent == null || domainComponent.trim().length() == 0) {
            return "";
        }
        return "DC=" + domainComponent;
    }

    public String getStreetAddress () {
        if (streetAddress == null || streetAddress.trim().length() == 0) {
            return "";
        }
        return "STREET=" + streetAddress;
    }

    public String getEmail () {
        if (email == null || email.trim().length() == 0) {
            return "";
        }
        return "E=" + email;
    }

    public X500Name toX500Name() {
        return new X500Name(toString());
    }

    public X500Principal toX500Principal() {
        return new X500Principal(toString());
    }

    @Override
    public String toString() {
        return (getCommonName().length() > 0 ? getCommonName() : "") +
               (getOrganizationalUnitName().length() > 0 ? ", " + getOrganizationalUnitName() : "") +
               (getOrganizationName().length() > 0 ? ", " + getOrganizationName() : "" ) +
               (getLocalityName().length() > 0 ? ", " + getLocalityName() : "" ) +
               (getStateOrProvince().length() > 0 ? ", " + getStateOrProvince() : "" ) +
               (getDomainComponent().length() > 0 ? ", " + getDomainComponent() : "" ) +
               (getStreetAddress().length() > 0 ? ", " + getStreetAddress() : "" ) +
               (getEmail().length() > 0 ? ", " + getEmail() : "" ) +
               (getCountryName().length() > 0 ? ", " + getCountryName() : "") ;
    }
}
