package org.cloudfoundry.identity.uaa.provider.saml;

/**
 * This class contains NameID format constants for SAML 1.1 and SAML 2.0.
 *
 * @see <a href="https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf">Saml 2.0 Doc</a>
 * Section 8.3 - Name Identifier Format Identifiers
 */
public final class SamlNameIdFormats {

    private static final String NAMEID_FORMAT_BASE = "urn:oasis:names:tc:SAML:%s:nameid-format:%s";

    /***************************************************************************
     * SAML 1.1 NameID Formats
     */
    private static final String NAMEID_VERSION_1_1 = "1.1";

    /**
     * URI: urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
     * <p/>
     * Indicates that the content of the element is in the form of an email address, specifically "addr-spec" as
     * defined in IETF RFC 2822 [RFC 2822] Section 3.4.1. An addr-spec has the form local-part@domain. Note
     * that an addr-spec has no phrase (such as a common name) before it, has no comment (text surrounded
     * in parentheses) after it, and is not surrounded by "<" and ">".
     */
    public static final String NAMEID_FORMAT_EMAIL = NAMEID_FORMAT_BASE.formatted(NAMEID_VERSION_1_1, "emailAddress");

    /**
     * URI: urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified
     * <p/>
     * The interpretation of the content of the element is left to individual implementations.
     */
    public static final String NAMEID_FORMAT_UNSPECIFIED = NAMEID_FORMAT_BASE.formatted(NAMEID_VERSION_1_1, "unspecified");

    /**
     * URI: urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName
     * <p/>
     * Indicates that the content of the element is in the form specified for the contents of the
     * <ds:X509SubjectName> element in the XML Signature Recommendation [XMLSig]. Implementors
     * <p>
     * should note that the XML Signature specification specifies encoding rules for X.509 subject names that
     * differ from the rules given in IETF RFC 2253 [RFC 2253].
     */
    public static final String NAMEID_FORMAT_X509SUBJECT = NAMEID_FORMAT_BASE.formatted(NAMEID_VERSION_1_1, "X509SubjectName");

    /**
     * URI: urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName
     * <p/>
     * Indicates that the content of the element is a Windows domain qualified name. A Windows domain
     * qualified user name is a string of the form "DomainName\UserName". The domain name and "\" separator
     * MAY be omitted.
     */
    public static final String NAMEID_FORMAT_WINDOWS_DQN = NAMEID_FORMAT_BASE.formatted(NAMEID_VERSION_1_1, "WindowsDomainQualifiedName");

    /***************************************************************************
     * SAML 2.0 NameID Formats
     */
    private static final String NAMEID_VERSION_2_0 = "2.0";

    /**
     * URI: urn:oasis:names:tc:SAML:2.0:nameid-format:persistent
     * <p/>
     * Indicates that the content of the element is a persistent opaque identifier for a principal that is specific to
     * an identity provider and a service provider or affiliation of service providers. Persistent name identifiers
     * generated by identity providers MUST be constructed using pseudo-random values that have no
     * discernible correspondence with the subject's actual identifier (for example, username). The intent is to
     * create a non-public, pair-wise pseudonym to prevent the discovery of the subject's identity or activities.
     * Persistent name identifier values MUST NOT exceed a length of 256 characters.
     * <p/>
     * The element's NameQualifier attribute, if present, MUST contain the unique identifier of the identity
     * provider that generated the identifier (see Section 8.3.6). It MAY be omitted if the value can be derived
     * from the context of the message containing the element, such as the issuer of a protocol message or an
     * assertion containing the identifier in its subject. Note that a different system entity might later issue its own
     * protocol message or assertion containing the identifier; the NameQualifier attribute does not change in
     * this case, but MUST continue to identify the entity that originally created the identifier (and MUST NOT be
     * omitted in such a case).
     * <p/>
     * The element's SPNameQualifier attribute, if present, MUST contain the unique identifier of the service
     * provider or affiliation of providers for whom the identifier was generated (see Section 8.3.6). It MAY be
     * omitted if the element is contained in a message intended only for consumption directly by the service
     * provider, and the value would be the unique identifier of that service provider.
     * The element's SPProvidedID attribute MUST contain the alternative identifier of the principal most
     * recently set by the service provider or affiliation, if any (see Section 3.6). If no such identifier has been
     * established, then the attribute MUST be omitted.
     * <p/>
     * Persistent identifiers are intended as a privacy protection mechanism; as such they MUST NOT be shared
     * in clear text with providers other than the providers that have established the shared identifier.
     * Furthermore, they MUST NOT appear in log files or similar locations without appropriate controls and
     * protections. Deployments without such requirements are free to use other kinds of identifiers in their
     * SAML exchanges, but MUST NOT overload this format with persistent but non-opaque values
     * <p/>
     * Note also that while persistent identifiers are typically used to reflect an account linking relationship
     * between a pair of providers, a service provider is not obligated to recognize or make use of the long term
     * nature of the persistent identifier or establish such a link. Such a "one-sided" relationship is not discernibly
     * different and does not affect the behavior of the identity provider or any processing rules specific to
     * persistent identifiers in the protocols defined in this specification.
     * <p/>
     * Finally, note that the NameQualifier and SPNameQualifier attributes indicate directionality of
     * creation, but not of use. If a persistent identifier is created by a particular identity provider, the
     * NameQualifier attribute value is permanently established at that time. If a service provider that receives
     * such an identifier takes on the role of an identity provider and issues its own assertion containing that
     * identifier, the NameQualifier attribute value does not change (and would of course not be omitted). It
     * might alternatively choose to create its own persistent identifier to represent the principal and link the two
     * values. This is a deployment decision.
     */
    public static final String NAMEID_FORMAT_PERSISTENT = NAMEID_FORMAT_BASE.formatted(NAMEID_VERSION_2_0, "persistent");

    /**
     * URI: urn:oasis:names:tc:SAML:2.0:nameid-format:transient
     * <p/>
     * Indicates that the content of the element is an identifier with transient semantics and SHOULD be treated
     * as an opaque and temporary value by the relying party. Transient identifier values MUST be generated in
     * accordance with the rules for SAML identifiers (see Section 1.3.4), and MUST NOT exceed a length of
     * 256 characters.
     * <p/>
     * The NameQualifier and SPNameQualifier attributes MAY be used to signify that the identifier
     * represents a transient and temporary pair-wise identifier. In such a case, they MAY be omitted in
     * accordance with the rules specified in Section 8.3.7.
     */
    public static final String NAMEID_FORMAT_TRANSIENT = NAMEID_FORMAT_BASE.formatted(NAMEID_VERSION_2_0, "transient");

    /**
     * URI: urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos
     * <p/>
     * Indicates that the content of the element is in the form of a Kerberos principal name using the format
     * name[/instance]@REALM. The syntax, format and characters allowed for the name, instance, and
     * realm are described in IETF RFC 1510 [RFC 1510].
     */
    public static final String NAMEID_FORMAT_KERBEROS = NAMEID_FORMAT_BASE.formatted(NAMEID_VERSION_2_0, "kerberos");

    /**
     * URI: urn:oasis:names:tc:SAML:2.0:nameid-format:entity
     * <p/>
     * Indicates that the content of the element is the identifier of an entity that provides SAML-based services
     * (such as a SAML authority, requester, or responder) or is a participant in SAML profiles (such as a service
     * provider supporting the browser SSO profile). Such an identifier can be used in the <Issuer> element to
     * identify the issuer of a SAML request, response, or assertion, or within the <NameID> element to make
     * assertions about system entities that can issue SAML requests, responses, and assertions. It can also be
     * used in other elements and attributes whose purpose is to identify a system entity in various protocol
     * exchanges.
     * <p/>
     * The syntax of such an identifier is a URI of not more than 1024 characters in length. It is
     * RECOMMENDED that a system entity use a URL containing its own domain name to identify itself.
     * The NameQualifier, SPNameQualifier, and SPProvidedID attributes MUST be omitted.
     */
    public static final String NAMEID_FORMAT_ENTITY = NAMEID_FORMAT_BASE.formatted(NAMEID_VERSION_2_0, "entity");

    private SamlNameIdFormats() {
        throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }
}
