package org.cloudfoundry.identity.uaa.oauth.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import org.cloudfoundry.identity.uaa.client.ClientJwtConfiguration;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoBuilder;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.oauth.beans.ApplicationContextProvider;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.oauth.OidcMetadataFetcher;
import org.cloudfoundry.identity.uaa.provider.oauth.OidcMetadataFetchingException;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManagerImpl;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationContext;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JwtClientAuthenticationTest {
    private static final String KEY_ID = "tokenKeyId";
    private static final String INVALID_CLIENT_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJjYmEyZmRlN2ZkYTg0YzMzYTdkZDQ5MWVmMzljZWY5NiIsImF1ZCI6WyJodHRwOi8vbG9jYWxob3N0OjgwODAvdWFhL29hdXRoL3Rva2VuIl0sInN1YiI6ImlkZW50aXR5IiwiaXNzIjoic29tZVRoaW5nIn0.HLXpsPJw0SvF8DcGmmifzJJLxX4hmfwILAtAFedk48c";
    private static final String INVALID_CLIENT_ALG = "eyJhbGciOiJIUzI1NiIsImtpZCI6InRva2VuS2V5SWQiLCJ0eXAiOiJKV1QifQ.eyJleHAiOjE2OTU4NDEyMDYsImp0aSI6ImRhMzdjYzFjMjkzOTQzMWE4YjUzZTI5MmZiMjYxMDZhIiwiYXVkIjpbImh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC91YWEvb2F1dGgvdG9rZW4iXSwic3ViIjoiaWRlbnRpdHkiLCJpc3MiOiJpZGVudGl0eSIsImlhdCI6MTY5NTg0MDc4NiwicmV2b2NhYmxlIjpmYWxzZX0.gFYuUjzupzeKNK2Uq3Ijp0rDIcJfI80wl3Pt5MSypPM";

    private OIDCIdentityProviderDefinition config;
    private final KeyInfoService keyInfoService = mock(KeyInfoService.class);
    private final OidcMetadataFetcher oidcMetadataFetcher = mock(OidcMetadataFetcher.class);
    private JwtClientAuthentication jwtClientAuthentication;

    @BeforeEach
    void setup() throws MalformedURLException, JOSEException {
        IdentityZoneHolder.set(IdentityZone.getUaa());
        jwtClientAuthentication = new JwtClientAuthentication(keyInfoService);
        config = new OIDCIdentityProviderDefinition();
        config.setTokenUrl(new URL("http://localhost:8080/uaa/oauth/token"));
        config.setRelyingPartyId("identity");
        config.setJwtClientAuthentication(true);
        mockKeyInfoService(null, JwtHelperX5tTest.CERTIFICATE_1);
        mockApplicationContext(Map.of());
    }

    @AfterEach
    void cleanup() {
        IdentityZoneHolder.clear();
    }

    @Test
    void getClientAssertion() throws ParseException {
        // When
        String clientAssertion = jwtClientAuthentication.getClientAssertion(config);
        // Then
        validateClientAssertionOidcComplaint(clientAssertion);
    }

    @Test
    void getClientAssertionUsingTrueBooleanConfig() throws ParseException {
        // Given
        config.setJwtClientAuthentication(true);
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        // When
        params = jwtClientAuthentication.getClientAuthenticationParameters(params, config);
        // Then
        assertThat(params).containsKey("client_assertion")
                .containsKey("client_assertion_type");
        String clientAssertion = params.get("client_assertion").get(0);
        validateClientAssertionOidcComplaint(clientAssertion);
        JWSHeader header = getJwtHeader(clientAssertion);
        assertThat(header.getKeyID()).isEqualTo(KEY_ID);
    }

    @Test
    void getClientAssertionUsingFalseBooleanConfig() {
        // Given
        config.setJwtClientAuthentication(false);
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        // When
        params = jwtClientAuthentication.getClientAuthenticationParameters(params, config);
        // Then
        assertThat(params).doesNotContainKey("client_assertion")
                .doesNotContainKey("client_assertion_type");
    }

    @Test
    void getClientAssertionUsingCustomConfig() throws ParseException {
        // Given
        Map<Object, Object> customClaims = Map.of("iss", "identity");
        config.setJwtClientAuthentication(customClaims);
        // When
        String clientAssertion = jwtClientAuthentication.getClientAssertion(config);
        // Then
        validateClientAssertionOidcComplaint(clientAssertion);
    }

    @Test
    void getClientAssertionRfc7523Complaint() throws ParseException {
        // Given
        Map<Object, Object> customClaims = new HashMap<>();
        customClaims.put("iss", "anotherIssuer");
        customClaims.put("aud", "ReceiverEndpoint");
        config.setJwtClientAuthentication(customClaims);
        // When
        String clientAssertion = jwtClientAuthentication.getClientAssertion(config);
        // Then
        validateClientAssertionRfc7523Complaint(clientAssertion, "anotherIssuer", "ReceiverEndpoint");
    }

    @Test
    void getClientAuthenticationParameters() throws ParseException {
        // Given
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        // When
        params = jwtClientAuthentication.getClientAuthenticationParameters(params, config);
        // Then
        assertThat(params).containsKey("client_assertion")
                .containsKey("client_assertion_type")
                .containsEntry("client_assertion_type", Collections.singletonList(JwtClientAuthentication.GRANT_TYPE));
        assertThat(params.get("client_assertion").get(0)).isNotNull();
        validateClientAssertionOidcComplaint(params.get("client_assertion").get(0));
    }

    @Test
    void getClientAuthenticationParametersNullParameter() {
        // When
        assertThat(jwtClientAuthentication.getClientAuthenticationParameters(null, null)).isNull();
    }

    @Test
    void getClientAuthenticationParametersNullJwtClientConfiguration() {
        // Given
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        config.setJwtClientAuthentication(null);
        // When
        assertThat(jwtClientAuthentication.getClientAuthenticationParameters(params, config)).isEqualTo(params);
    }

    @Test
    void getClientAssertionUnknownSingingKey() {
        // Given
        Map<Object, Object> customClaims = new HashMap<>();
        customClaims.put("kid", "wrong-key-id");
        config.setJwtClientAuthentication(customClaims);

        assertThatThrownBy(() -> jwtClientAuthentication.getClientAssertion(config))
                .isExactlyInstanceOf(BadCredentialsException.class);
    }

    @Test
    void getClientAssertionUsingCustomSingingKeyFromEnvironment() throws ParseException, JOSEException {
        // Given: register 2 keys
        mockKeyInfoService("key-id-321", JwtHelperX5tTest.CERTIFICATE_1);
        Map<Object, Object> customClaims = new HashMap<>();
        // reference to customer one key-id-321 and set default
        customClaims.put("kid", "${jwt.client.kid:" + KEY_ID + "}");
        config.setJwtClientAuthentication(customClaims);
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        Map<String, Object> keyMap = Map.of("jwt.client.kid", "key-id-321");
        mockApplicationContext(keyMap);
        // When
        params = jwtClientAuthentication.getClientAuthenticationParameters(params, config);
        // Then
        assertThat(params).containsKey("client_assertion")
                .containsKey("client_assertion_type");
        String clientAssertion = params.get("client_assertion").get(0);
        validateClientAssertionOidcComplaint(clientAssertion);
        JWSHeader header = getJwtHeader(clientAssertion);
        assertThat(header.getKeyID()).isEqualTo("key-id-321");
        assertThat(header.getJWKURL()).isNull();
    }

    @Test
    void getClientAssertionUsingCustomSingingKeyFromEnvironmentNoDefault() throws ParseException, JOSEException {
        // Given: register 2 keys
        mockKeyInfoService("key-id-321", JwtHelperX5tTest.CERTIFICATE_1);
        Map<Object, Object> customClaims = new HashMap<>();
        // reference to customer one key-id-321
        customClaims.put("kid", "${jwt.client.kid}");
        config.setJwtClientAuthentication(customClaims);
        mockApplicationContext(Map.of("jwt.client.kid", "key-id-321"));
        // When
        MultiValueMap<String, String> params = jwtClientAuthentication.getClientAuthenticationParameters(new LinkedMultiValueMap<>(), config);
        // Then
        assertThat(params).containsKey("client_assertion")
                .containsKey("client_assertion_type");
        String clientAssertion = params.get("client_assertion").get(0);
        validateClientAssertionOidcComplaint(clientAssertion);
        JWSHeader header = getJwtHeader(clientAssertion);
        assertThat(header.getKeyID()).isEqualTo("key-id-321");
        assertThat(header.getJWKURL()).isNull();
    }

    @Test
    void getClientAssertionUsingCustomSingingKeyFromEnvironmentButEntryIsMissing() throws JOSEException {
        // Given: register 2 keys
        mockKeyInfoService("key-id-321", JwtHelperX5tTest.CERTIFICATE_1);
        Map<Object, Object> customClaims = new HashMap<>();
        // reference in jwtClientAuthentication to a customer key, but this does not exist, then use default KEY_ID
        customClaims.put("kid", "${jwt.client.kid:" + KEY_ID + "}");
        config.setJwtClientAuthentication(customClaims);
        // empty application context
        mockApplicationContext(Map.of());
        // Then
        LinkedMultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        assertThatThrownBy(() -> jwtClientAuthentication.getClientAuthenticationParameters(params, config))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("Missing referenced signing entry");
    }

    @Test
    void getClientAssertionUsingCustomSingingKeyFromEnvironmentButNotInDefaultZone() throws JOSEException {
        // Given: register 2 keys
        mockKeyInfoService("key-id-321", JwtHelperX5tTest.CERTIFICATE_1);
        Map<Object, Object> customClaims = new HashMap<>();
        // reference in jwtClientAuthentication to a custom key, but call it not from UAA zone
        customClaims.put("kid", "${jwt.client.kid}");
        config.setJwtClientAuthentication(customClaims);
        mockApplicationContext(Map.of("jwt.client.kid", "key-id-321"));
        IdentityZone currentZone = IdentityZone.getUaa();
        // modify to custom zone
        currentZone.setId(new AlphanumericRandomValueStringGenerator().generate());
        currentZone.setSubdomain(new AlphanumericRandomValueStringGenerator().generate());
        IdentityZoneHolder.set(currentZone);
        // Expect
        LinkedMultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        assertThatThrownBy(() -> jwtClientAuthentication.getClientAuthenticationParameters(params, config))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("Missing requested signing key");
    }

    @Test
    void getClientAssertionCustomSingingKeyButNoCertificate() throws ParseException, JOSEException {
        // Given
        mockKeyInfoService("myKey", null);
        Map<Object, Object> customClaims = new HashMap<>();
        customClaims.put("kid", "myKey");
        config.setJwtClientAuthentication(customClaims);
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        // When
        params = jwtClientAuthentication.getClientAuthenticationParameters(params, config);
        // Then
        assertThat(params).containsKey("client_assertion")
                .containsKey("client_assertion_type");
        String clientAssertion = params.get("client_assertion").get(0);
        validateClientAssertionOidcComplaint(clientAssertion);
        JWSHeader header = getJwtHeader(clientAssertion);
        assertThat(header.getKeyID()).isEqualTo("myKey");
        assertThat(header.getJWKURL()).hasToString("http://localhost:8080/uaa/token_key");
    }

    @Test
    void getClientAssertionUsingCustomSingingPrivateKeyFromEnvironment() throws ParseException, JOSEException {
        // Given: register 2 keys
        mockKeyInfoService("key-id-321", JwtHelperX5tTest.CERTIFICATE_1);
        // add reference in jwtClientAuthentication to customer one key-id-321
        Map<Object, Object> customClaims = new HashMap<>();
        customClaims.put("kid", "${jwt.client.kid}");
        customClaims.put("key", "${jwt.client.key}");
        customClaims.put("cert", "${jwt.client.cert}");
        config.setJwtClientAuthentication(customClaims);
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        Map<String, Object> keyMap = Map.of("jwt.client.kid", "key-id-321",
                "jwt.client.key", JwtHelperX5tTest.SIGNING_KEY_1,
                "jwt.client.cert", JwtHelperX5tTest.CERTIFICATE_1);
        mockApplicationContext(keyMap);
        // When
        params = jwtClientAuthentication.getClientAuthenticationParameters(params, config);
        // Then
        assertThat(params).containsKey("client_assertion")
                .containsKey("client_assertion_type");
        String clientAssertion = params.get("client_assertion").get(0);
        validateClientAssertionOidcComplaint(clientAssertion);
        JWSHeader header = getJwtHeader(clientAssertion);
        assertThat(header.getKeyID()).isEqualTo("key-id-321");
        assertThat(header.getJWKURL()).isNull();
    }

    @Test
    void getClientAssertionUsingCustomSingingPrivateKeyFromEnvironmentDisabledForCustomZone() throws JOSEException {
        arrangeCustomIdz();

        // Given: register 2 keys
        mockKeyInfoService("key-id-321", JwtHelperX5tTest.CERTIFICATE_1);

        // add reference in jwtClientAuthentication to customer one key-id-321
        Map<Object, Object> customClaims = new HashMap<>();
        customClaims.put("kid", "${jwt.client.kid}");
        customClaims.put("key", "${jwt.client.key}");
        customClaims.put("cert", "${jwt.client.cert}");
        config.setJwtClientAuthentication(customClaims);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        final Map<String, Object> keyMap = Map.of(
                "jwt.client.kid", "key-id-321",
                "jwt.client.key", JwtHelperX5tTest.SIGNING_KEY_1,
                "jwt.client.cert", JwtHelperX5tTest.CERTIFICATE_1
        );
        mockApplicationContext(keyMap);

        assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() ->
                jwtClientAuthentication.getClientAuthenticationParameters(params, config, false)
        ).withMessage("Missing requested signing key");
    }

    @Test
    void getClientAssertionUsingCustomSingingPrivateKeyFromEnvironmentEnabledForCustomZone() throws ParseException, JOSEException {
        arrangeCustomIdz();

        // Given: register 2 keys
        mockKeyInfoService("key-id-321", JwtHelperX5tTest.CERTIFICATE_1);

        // add reference in jwtClientAuthentication to customer one key-id-321
        Map<Object, Object> customClaims = new HashMap<>();
        customClaims.put("kid", "${jwt.client.kid}");
        customClaims.put("key", "${jwt.client.key}");
        customClaims.put("cert", "${jwt.client.cert}");
        config.setJwtClientAuthentication(customClaims);

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        final Map<String, Object> keyMap = Map.of(
                "jwt.client.kid", "key-id-321",
                "jwt.client.key", JwtHelperX5tTest.SIGNING_KEY_1,
                "jwt.client.cert", JwtHelperX5tTest.CERTIFICATE_1
        );
        mockApplicationContext(keyMap);

        // When
        params = jwtClientAuthentication.getClientAuthenticationParameters(params, config, true);

        // Then
        assertThat(params).containsKey("client_assertion")
                .containsKey("client_assertion_type");
        final String clientAssertion = params.get("client_assertion").get(0);
        validateClientAssertionOidcComplaint(clientAssertion);
        final JWSHeader header = getJwtHeader(clientAssertion);
        assertThat(header.getKeyID()).isEqualTo("key-id-321");
        assertThat(header.getJWKURL()).isNull();
    }

    private static void arrangeCustomIdz() {
        final IdentityZone customZone = new IdentityZone();
        customZone.setId(new AlphanumericRandomValueStringGenerator(8).generate().toLowerCase());
        new IdentityZoneManagerImpl().setCurrentIdentityZone(customZone);
    }

    @Test
    void getClientIdOfClientAssertion() {
        // When
        String clientAssertion = jwtClientAuthentication.getClientAssertion(config);
        // Then
        assertThat(JwtClientAuthentication.getClientId(clientAssertion)).isEqualTo("identity");
    }

    @Test
    void requestInvalidateClientAssertion() throws Exception {
        // Then
        assertThat(jwtClientAuthentication.validateClientJwt(getMockedRequestParameter("test", INVALID_CLIENT_JWT), getMockedClientJwtConfiguration(null), "identity")).isFalse();
    }

    @Test
    void wrongAssertionInvalidateClientId() {
        // Given
        jwtClientAuthentication = new JwtClientAuthentication(keyInfoService, oidcMetadataFetcher);
        // Then
        assertThatThrownBy(() -> jwtClientAuthentication.validateClientJwt(getMockedRequestParameter(null, jwtClientAuthentication.getClientAssertion(config)),
                // pass a different client_id to the provided one from client_assertion JWT
                getMockedClientJwtConfiguration(null), "wrong_client_id"))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("Wrong client_assertion");
    }

    @Test
    void badAlgorithmInvalidateClientId() throws Exception {
        // Given
        jwtClientAuthentication = new JwtClientAuthentication(keyInfoService, oidcMetadataFetcher);
        ClientJwtConfiguration clientJwtConfiguration = getMockedClientJwtConfiguration(null);
        when(oidcMetadataFetcher.fetchWebKeySet(clientJwtConfiguration)).thenReturn(clientJwtConfiguration.getJwkSet());
        // Then
        assertThatThrownBy(() -> jwtClientAuthentication.validateClientJwt(getMockedRequestParameter(null, INVALID_CLIENT_ALG),
                clientJwtConfiguration, "identity"))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("Bad client_assertion algorithm");
    }

    @Test
    void oidcFetchFailed() throws Exception {
        // Given
        jwtClientAuthentication = new JwtClientAuthentication(keyInfoService, oidcMetadataFetcher);
        ClientJwtConfiguration clientJwtConfiguration = getMockedClientJwtConfiguration(null);
        when(oidcMetadataFetcher.fetchWebKeySet(clientJwtConfiguration)).thenThrow(new OidcMetadataFetchingException(""));
        // Then
        assertThatThrownBy(() -> jwtClientAuthentication.validateClientJwt(getMockedRequestParameter(null, jwtClientAuthentication.getClientAssertion(config)),
                clientJwtConfiguration, "identity"))
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("Bad client_assertion");
    }

    @Test
    void untrustedClientAssertion() throws Exception {
        // Given
        jwtClientAuthentication = new JwtClientAuthentication(keyInfoService, oidcMetadataFetcher);
        // create client assertion with key ids which won't map to provide JWT,
        // lead to failing validateClientJWToken check
        ClientJwtConfiguration clientJwtConfiguration = getMockedClientJwtConfiguration("extId");
        when(oidcMetadataFetcher.fetchWebKeySet(clientJwtConfiguration)).thenReturn(clientJwtConfiguration.getJwkSet());
        String clientAssertion = jwtClientAuthentication.getClientAssertion(config);
        // When
        assertThatThrownBy(() -> jwtClientAuthentication.validateClientJwt(getMockedRequestParameter(null, clientAssertion), clientJwtConfiguration, "identity"))
                // Then, expect key resolution error because of not matching configured keys to JWT kid
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("Untrusted client_assertion");
    }

    @Test
    void signatureInvalidateClientAssertion() throws Exception {
        // Given
        jwtClientAuthentication = new JwtClientAuthentication(keyInfoService, oidcMetadataFetcher);
        ClientJwtConfiguration clientJwtConfiguration = getMockedClientJwtConfiguration(null);
        when(oidcMetadataFetcher.fetchWebKeySet(clientJwtConfiguration)).thenReturn(clientJwtConfiguration.getJwkSet());
        String clientAssertion = jwtClientAuthentication.getClientAssertion(config);
        // When
        assertThatThrownBy(() -> jwtClientAuthentication.validateClientJwt(getMockedRequestParameter(null, clientAssertion), clientJwtConfiguration, "identity"))
                // Then, expect signature failed because mockKeyInfoService creates a corrupted signature
                .isInstanceOf(BadCredentialsException.class)
                .hasMessage("Unauthorized client_assertion");
    }

    @Test
    void getClientIdOfInvalidClientAssertion() {
        // Then
        assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> JwtClientAuthentication.getClientId(INVALID_CLIENT_JWT));
        assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() -> JwtClientAuthentication.getClientId("eyXXX"));
    }

    private void mockKeyInfoService(String keyId, String x509Certificate) throws JOSEException {
        KeyInfo keyInfo = mock(KeyInfo.class);
        JWSSigner signer = mock(JWSSigner.class);
        if (keyId != null) {
            KeyInfo customKeyInfo = mock(KeyInfo.class);
            when(customKeyInfo.keyId()).thenReturn(keyId);
            when(keyInfoService.getKey(keyId)).thenReturn(customKeyInfo);
            when(customKeyInfo.algorithm()).thenReturn("RS256");
            when(customKeyInfo.keyURL()).thenReturn("http://localhost:8080/uaa/token_key");
            when(customKeyInfo.getSigner()).thenReturn(signer);
            when(customKeyInfo.verifierCertificate()).thenReturn(x509Certificate != null ? Optional.of(X509CertUtils.parse(x509Certificate)) : Optional.empty());
        }
        when(keyInfo.keyId()).thenReturn(KEY_ID);
        when(keyInfoService.getKey(KEY_ID)).thenReturn(keyInfo);
        when(keyInfoService.getActiveKey()).thenReturn(keyInfo);
        when(keyInfo.algorithm()).thenReturn("RS256");
        when(keyInfo.keyURL()).thenReturn("http://localhost:8080/uaa/token_key");
        when(keyInfo.getSigner()).thenReturn(signer);
        when(keyInfo.verifierCertificate()).thenReturn(x509Certificate != null ? Optional.of(X509CertUtils.parse(x509Certificate)) : Optional.of(X509CertUtils.parse(JwtHelperX5tTest.CERTIFICATE_1)));
        when(signer.supportedJWSAlgorithms()).thenReturn(Set.of(JWSAlgorithm.RS256));
        when(signer.sign(any(), any())).thenReturn(new Base64URL("dummy"));
    }

    private void mockApplicationContext(Map<String, Object> environmentMap) {
        ApplicationContext applicationContext = mock(ApplicationContext.class);
        Environment environment = mock(Environment.class);
        when(applicationContext.getEnvironment()).thenReturn(environment);
        environmentMap.keySet().forEach(e -> when(environment.getProperty(e)).thenReturn((String) environmentMap.get(e)));
        new ApplicationContextProvider().setApplicationContext(applicationContext);
    }

    private static JWSHeader getJwtHeader(String jwtString) throws ParseException {
        JWT jwt = JWTParser.parse(jwtString);
        return (JWSHeader) jwt.getHeader();
    }

    private static void validateClientAssertionOidcComplaint(String clientAssertion) throws ParseException {
        JWTClaimsSet jwtClaimsSet = JWTParser.parse(clientAssertion).getJWTClaimsSet();
        assertThat(jwtClaimsSet.getAudience()).isEqualTo(Collections.singletonList("http://localhost:8080/uaa/oauth/token"));
        assertThat(jwtClaimsSet.getSubject()).isEqualTo("identity");
        assertThat(jwtClaimsSet.getIssuer()).isEqualTo("identity");
    }

    private static void validateClientAssertionRfc7523Complaint(String clientAssertion, String iss, String aud) throws ParseException {
        JWTClaimsSet jwtClaimsSet = JWTParser.parse(clientAssertion).getJWTClaimsSet();
        assertThat(jwtClaimsSet.getAudience()).isEqualTo(Collections.singletonList(aud));
        assertThat(jwtClaimsSet.getIssuer()).isEqualTo(iss);
        assertThat(jwtClaimsSet.getSubject()).isEqualTo("identity");
    }

    private static Map<String, String[]> getMockedRequestParameter(String type, String assertion) {
        Map<String, String[]> requestParameters = new HashMap<>();
        if (type != null) {
            requestParameters.put(JwtClientAuthentication.CLIENT_ASSERTION_TYPE, new String[]{type});
        } else {
            requestParameters.put(JwtClientAuthentication.CLIENT_ASSERTION_TYPE, new String[]{JwtClientAuthentication.GRANT_TYPE});
        }
        requestParameters.put(JwtClientAuthentication.CLIENT_ASSERTION, new String[]{assertion});
        return requestParameters;
    }

    private static ClientJwtConfiguration getMockedClientJwtConfiguration(String keyId) throws ParseException {
        KeyInfo keyInfo = KeyInfoBuilder.build(keyId != null ? keyId : "tokenKeyId", JwtHelperX5tTest.SIGNING_KEY_1, "http://localhost:8080/uaa");
        return ClientJwtConfiguration.parse(JWK.parse(keyInfo.getJwkMap()).toString());
    }
}
