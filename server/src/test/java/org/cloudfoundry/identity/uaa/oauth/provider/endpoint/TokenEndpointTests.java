package org.cloudfoundry.identity.uaa.oauth.provider.endpoint;

import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.UaaOauth2RequestValidator;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidClientException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidGrantException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidRequestException;
import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetailsService;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.error.DefaultWebResponseExceptionTranslator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.HttpRequestMethodNotSupportedException;

import java.security.Principal;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
@ExtendWith(MockitoExtension.class)
class TokenEndpointTests {

    @Mock
    private TokenGranter tokenGranter;

    @Mock
    private OAuth2RequestFactory authorizationRequestFactory;

    @Mock
    private ClientDetailsService clientDetailsService;

    private String clientId = "client";
    private UaaClientDetails clientDetails = new UaaClientDetails();

    private TokenEndpoint endpoint;

    private Principal clientAuthentication = new UsernamePasswordAuthenticationToken("client", null,
            Collections.singleton(new SimpleGrantedAuthority("ROLE_CLIENT")));

    private TokenRequest createFromParameters(Map<String, String> parameters) {
        return new TokenRequest(parameters, parameters.get(OAuth2Utils.CLIENT_ID),
                OAuth2Utils.parseParameterList(parameters.get(OAuth2Utils.SCOPE)),
                parameters.get(OAuth2Utils.GRANT_TYPE));
    }

    @BeforeEach
    void init() {
        endpoint = new TokenEndpoint();
        endpoint.setTokenGranter(tokenGranter);
        endpoint.setOAuth2RequestFactory(authorizationRequestFactory);
        endpoint.setClientDetailsService(clientDetailsService);
        clientDetails.setScope(Set.of("admin", "read", "write"));
    }

    @Test
    void testSetterAndGetter() throws Exception {
        endpoint.setProviderExceptionHandler(new DefaultWebResponseExceptionTranslator());
        assertNotNull(endpoint.getExceptionTranslator());
        endpoint.setOAuth2RequestFactory(null);
        endpoint.afterPropertiesSet();
        assertNotNull(endpoint.getOAuth2RequestFactory());
        assertEquals(endpoint.getDefaultOAuth2RequestFactory(), endpoint.getOAuth2RequestFactory());
    }

    @Test
    void testGetAccessTokenWithNoClientId() {
        HashMap<String, String> parameters = new HashMap<>();
        parameters.put(OAuth2Utils.GRANT_TYPE, "authorization_code");

        OAuth2AccessToken expectedToken = new DefaultOAuth2AccessToken("FOO");
        when(tokenGranter.grant(eq("authorization_code"), any(TokenRequest.class))).thenReturn(
                expectedToken);
        @SuppressWarnings("unchecked")
        Map<String, String> anyMap = any(Map.class);
        when(authorizationRequestFactory.createTokenRequest(anyMap, any())).thenReturn(
                createFromParameters(parameters));

        clientAuthentication = new UsernamePasswordAuthenticationToken(null, null,
                Collections.singleton(new SimpleGrantedAuthority("ROLE_CLIENT")));
        ResponseEntity<OAuth2AccessToken> response = endpoint.postAccessToken(clientAuthentication, parameters);

        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        OAuth2AccessToken body = response.getBody();
        assertEquals(body, expectedToken);
        assertTrue(body.getTokenType() != null, "Wrong body: " + body);
    }

    @Test
    void testGetAccessTokenWithScope() {

        when(clientDetailsService.loadClientByClientId(clientId)).thenReturn(clientDetails);

        HashMap<String, String> parameters = new HashMap<>();
        parameters.put("client_id", clientId);
        parameters.put("scope", "read");
        parameters.put("grant_type", "authorization_code");
        parameters.put("code", "kJAHDFG");

        OAuth2AccessToken expectedToken = new DefaultOAuth2AccessToken("FOO");
        ArgumentCaptor<TokenRequest> captor = ArgumentCaptor.forClass(TokenRequest.class);

        when(tokenGranter.grant(eq("authorization_code"), captor.capture())).thenReturn(expectedToken);
        @SuppressWarnings("unchecked")
        Map<String, String> anyMap = any(Map.class);
        when(authorizationRequestFactory.createTokenRequest(anyMap, eq(clientDetails))).thenReturn(
                createFromParameters(parameters));

        ResponseEntity<OAuth2AccessToken> response = endpoint.postAccessToken(clientAuthentication, parameters);

        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        OAuth2AccessToken body = response.getBody();
        assertEquals(body, expectedToken);
        assertTrue(body.getTokenType() != null, "Wrong body: " + body);
        assertTrue(captor.getValue().getScope().isEmpty(), "Scope of token request not cleared");
    }

    @Test
    void testGetAccessTokenWithUnsupportedRequestParameters() {
        assertThrows(HttpRequestMethodNotSupportedException.class, () ->
                endpoint.getAccessToken(clientAuthentication, new HashMap<>()));
    }

    @Test
    void testGetAccessTokenWithSupportedRequestParametersNotPost() throws HttpRequestMethodNotSupportedException {
        endpoint.setAllowedRequestMethods(new HashSet<>(Arrays.asList(HttpMethod.GET)));
        HashMap<String, String> parameters = new HashMap<>();
        parameters.put("client_id", clientId);
        parameters.put("scope", "read");
        parameters.put("grant_type", "authorization_code");
        parameters.put("code", "kJAHDFG");

        OAuth2AccessToken expectedToken = new DefaultOAuth2AccessToken("FOO");
        when(tokenGranter.grant(eq("authorization_code"), any(TokenRequest.class))).thenReturn(
                expectedToken);
        @SuppressWarnings("unchecked")
        Map<String, String> anyMap = any(Map.class);
        when(authorizationRequestFactory.createTokenRequest(anyMap, any())).thenReturn(
                createFromParameters(parameters));

        ResponseEntity<OAuth2AccessToken> response = endpoint.getAccessToken(clientAuthentication, parameters);
        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        OAuth2AccessToken body = response.getBody();
        assertEquals(body, expectedToken);
        assertTrue(body.getTokenType() != null, "Wrong body: " + body);
    }

    @Test
    void testImplicitGrant() {
        assertThrows(InvalidGrantException.class, () -> {
            HashMap<String, String> parameters = new HashMap<>();
            parameters.put(OAuth2Utils.GRANT_TYPE, "implicit");
            parameters.put("client_id", clientId);
            parameters.put("scope", "read");
            @SuppressWarnings("unchecked")
            Map<String, String> anyMap = any(Map.class);
            when(authorizationRequestFactory.createTokenRequest(anyMap, eq(clientDetails))).thenReturn(
                    createFromParameters(parameters));
            when(clientDetailsService.loadClientByClientId(clientId)).thenReturn(clientDetails);
            endpoint.postAccessToken(clientAuthentication, parameters);
        });
    }

    // gh-1268
    @Test
    void testGetAccessTokenReturnsHeaderContentTypeJson() {
        when(clientDetailsService.loadClientByClientId(clientId)).thenReturn(clientDetails);

        HashMap<String, String> parameters = new HashMap<>();
        parameters.put("client_id", clientId);
        parameters.put("scope", "read");
        parameters.put("grant_type", "authorization_code");
        parameters.put("code", "kJAHDFG");

        OAuth2AccessToken expectedToken = new DefaultOAuth2AccessToken("FOO");

        when(tokenGranter.grant(eq("authorization_code"), any(TokenRequest.class))).thenReturn(expectedToken);

        when(authorizationRequestFactory.createTokenRequest(any(Map.class), eq(clientDetails))).thenReturn(
                createFromParameters(parameters));

        ResponseEntity<OAuth2AccessToken> response = endpoint.postAccessToken(clientAuthentication, parameters);

        assertNotNull(response);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals("application/json;charset=UTF-8", response.getHeaders().get("Content-Type").iterator().next());
    }

    @Test
    void testRefreshTokenGrantTypeWithoutRefreshTokenParameter() {
        assertThrows(InvalidRequestException.class, () -> {
            when(clientDetailsService.loadClientByClientId(clientId)).thenReturn(clientDetails);

            HashMap<String, String> parameters = new HashMap<>();
            parameters.put("client_id", clientId);
            parameters.put("scope", "read");
            parameters.put("grant_type", "refresh_token");

            when(authorizationRequestFactory.createTokenRequest(any(Map.class), eq(clientDetails))).thenReturn(
                    createFromParameters(parameters));

            endpoint.postAccessToken(clientAuthentication, parameters);
        });
    }

    @Test
    void testGetAccessTokenWithRefreshToken() {
        when(clientDetailsService.loadClientByClientId(clientId)).thenReturn(clientDetails);

        HashMap<String, String> parameters = new HashMap<>();
        parameters.put("client_id", clientId);
        parameters.put("scope", "read");
        parameters.put("grant_type", "refresh_token");
        parameters.put("refresh_token", "kJAHDFG");

        OAuth2AccessToken expectedToken = new DefaultOAuth2AccessToken("FOO");

        when(tokenGranter.grant(eq("refresh_token"), any(TokenRequest.class))).thenReturn(expectedToken);

        when(authorizationRequestFactory.createTokenRequest(any(Map.class), eq(clientDetails))).thenReturn(
                createFromParameters(parameters));

        ResponseEntity<OAuth2AccessToken> response = endpoint.postAccessToken(clientAuthentication, parameters);

        assertEquals(expectedToken, response.getBody());
    }

    @Test
    void testPostAccessException() {
        assertThrows(InsufficientAuthenticationException.class, () ->
                endpoint.postAccessToken(null, Collections.emptyMap()));
    }

    @Test
    void testGetClientIdException() {
        assertThrows(InsufficientAuthenticationException.class, () ->
                endpoint.getClientId(new UsernamePasswordAuthenticationToken("FOO", "bar")));
    }

    @Test
    void testGetClientId() {
        OAuth2Request oAuth2Request = mock(OAuth2Request.class);
        OAuth2Authentication oAuth2Authentication = mock(OAuth2Authentication.class);
        when(oAuth2Authentication.getOAuth2Request()).thenReturn(oAuth2Request);
        when(oAuth2Authentication.isAuthenticated()).thenReturn(true);
        when(oAuth2Request.getClientId()).thenReturn("FOO");
        assertEquals("FOO", endpoint.getClientId(oAuth2Authentication));
    }

    @Test
    void testExceptions() throws Exception {
        endpoint.setOAuth2RequestValidator(new UaaOauth2RequestValidator());
        assertEquals("server_error", endpoint.handleException(new Exception("exception")).getBody().getOAuth2ErrorCode());
    }

    @Test
    void testInvalidClient() throws Exception {
        assertEquals("invalid_client", endpoint.handleException(new InvalidClientException("exception")).getBody().getOAuth2ErrorCode());
    }

    @Test
    void testInvalidClientException() throws Exception {
        assertEquals("invalid_client", endpoint.handleClientRegistrationException(new InvalidClientException("exception")).getBody().getOAuth2ErrorCode());
    }

    @Test
    void testNotSupported() throws Exception {
        assertEquals("method_not_allowed", endpoint.handleHttpRequestMethodNotSupportedException(new HttpRequestMethodNotSupportedException("exception")).getBody().getOAuth2ErrorCode());
    }
}
