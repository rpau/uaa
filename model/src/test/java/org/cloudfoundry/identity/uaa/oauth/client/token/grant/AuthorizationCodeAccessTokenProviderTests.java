package org.cloudfoundry.identity.uaa.oauth.client.token.grant;

import org.cloudfoundry.identity.uaa.oauth.client.grant.AuthorizationCodeAccessTokenProvider;
import org.cloudfoundry.identity.uaa.oauth.client.resource.AuthorizationCodeResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2ProtectedResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.UserRedirectRequiredException;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidRequestException;
import org.cloudfoundry.identity.uaa.oauth.token.AccessTokenRequest;
import org.cloudfoundry.identity.uaa.oauth.token.DefaultAccessTokenRequest;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class AuthorizationCodeAccessTokenProviderTests {

    private final MultiValueMap<String, String> params = new LinkedMultiValueMap<>();

    private final AuthorizationCodeAccessTokenProvider provider = new AuthorizationCodeAccessTokenProvider() {
        @Override
        protected OAuth2AccessToken retrieveToken(AccessTokenRequest request, OAuth2ProtectedResourceDetails resource,
                                                  MultiValueMap<String, String> form, HttpHeaders headers) {
            params.putAll(form);
            return new DefaultOAuth2AccessToken("FOO");
        }
    };

    private final AuthorizationCodeResourceDetails resource = new AuthorizationCodeResourceDetails();

    @Test
    public void supportsResource() {
        assertTrue(provider.supportsResource(new AuthorizationCodeResourceDetails()));
    }

    @Test
    public void getUserApproval() {
        assertNotNull(provider.getUserApprovalSignal(new AuthorizationCodeResourceDetails()));
    }

    @Test
    public void supportsRefresh() {
        assertTrue(provider.supportsRefresh(new AuthorizationCodeResourceDetails()));
    }

    @Test
    public void refreshAccessToken() {
        assertEquals("FOO", provider.refreshAccessToken(new AuthorizationCodeResourceDetails(), new DefaultOAuth2RefreshToken(""), new DefaultAccessTokenRequest(
                Collections.emptyMap())).getValue());
    }

    @Test
    public void testGetAccessToken() {
        AccessTokenRequest request = new DefaultAccessTokenRequest();
        request.setAuthorizationCode("foo");
        request.setPreservedState(new Object());
        resource.setAccessTokenUri("http://localhost/oauth/token");
        assertEquals("FOO", provider.obtainAccessToken(resource, request).getValue());
    }

    @Test
    public void testGetCode() {
        assertThrows(IllegalArgumentException.class, () -> {
            AccessTokenRequest request = new DefaultAccessTokenRequest();
            request.setAuthorizationCode(null);
            request.setPreservedState(new Object());
            request.setStateKey("key");
            resource.setAccessTokenUri("http://localhost/oauth/token");
            assertEquals("FOO", provider.obtainAccessToken(resource, request).getValue());
        });
    }

    @Test
    public void testGetAccessTokenFailsWithNoState() {
        assertThrows(InvalidRequestException.class, () -> {
            AccessTokenRequest request = new DefaultAccessTokenRequest();
            request.setAuthorizationCode("foo");
            resource.setAccessTokenUri("http://localhost/oauth/token");
            assertEquals("FOO", provider.obtainAccessToken(resource, request).getValue());
        });
    }

    @Test
    public void testRedirectToAuthorizationEndpoint() {
        AccessTokenRequest request = new DefaultAccessTokenRequest();
        request.setCurrentUri("/come/back/soon");
        resource.setUserAuthorizationUri("http://localhost/oauth/authorize");
        try {
            provider.obtainAccessToken(resource, request);
            fail("Expected UserRedirectRequiredException");
        } catch (UserRedirectRequiredException e) {
            assertEquals("http://localhost/oauth/authorize", e.getRedirectUri());
            assertEquals("/come/back/soon", e.getStateToPreserve());
        }
    }

    // A missing redirect just means the server has to deal with it
    @Test
    public void testRedirectNotSpecified() {
        assertThrows(UserRedirectRequiredException.class, () -> {
            AccessTokenRequest request = new DefaultAccessTokenRequest();
            resource.setUserAuthorizationUri("http://localhost/oauth/authorize");
            provider.obtainAccessToken(resource, request);
        });
    }

    @Test
    public void testGetAccessTokenRequest() {
        AccessTokenRequest request = new DefaultAccessTokenRequest();
        request.setAuthorizationCode("foo");
        request.setStateKey("bar");
        request.setPreservedState(new Object());
        resource.setAccessTokenUri("http://localhost/oauth/token");
        resource.setPreEstablishedRedirectUri("https://anywhere.com");
        assertEquals("FOO", provider.obtainAccessToken(resource, request).getValue());
        // System.err.println(params);
        assertEquals("authorization_code", params.getFirst("grant_type"));
        assertEquals("foo", params.getFirst("code"));
        assertEquals("https://anywhere.com", params.getFirst("redirect_uri"));
        // State is not set in token request
        assertEquals(null, params.getFirst("state"));
    }
}
