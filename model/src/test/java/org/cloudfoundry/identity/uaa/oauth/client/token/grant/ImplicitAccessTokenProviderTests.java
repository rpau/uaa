package org.cloudfoundry.identity.uaa.oauth.client.token.grant;

import org.cloudfoundry.identity.uaa.oauth.client.grant.ImplicitAccessTokenProvider;
import org.cloudfoundry.identity.uaa.oauth.client.resource.ImplicitResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2ProtectedResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.token.AccessTokenRequest;
import org.cloudfoundry.identity.uaa.oauth.token.DefaultAccessTokenRequest;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class ImplicitAccessTokenProviderTests {

    private final MultiValueMap<String, String> params = new LinkedMultiValueMap<>();

    private final ImplicitAccessTokenProvider provider = new ImplicitAccessTokenProvider() {
        @Override
        protected OAuth2AccessToken retrieveToken(AccessTokenRequest request, OAuth2ProtectedResourceDetails resource,
                                                  MultiValueMap<String, String> form, HttpHeaders headers) {
            params.putAll(form);
            return new DefaultOAuth2AccessToken("FOO");
        }
    };

    private final ImplicitResourceDetails resource = new ImplicitResourceDetails();

    @Test
    public void testRedirectNotSpecified() {
        assertThrows(IllegalStateException.class, () -> {
            AccessTokenRequest request = new DefaultAccessTokenRequest();
            provider.obtainAccessToken(resource, request);
        });
    }

    @Test
    public void supportsResource() {
        assertTrue(provider.supportsResource(new ImplicitResourceDetails()));
    }

    @Test
    public void supportsRefresh() {
        assertFalse(provider.supportsRefresh(new ImplicitResourceDetails()));
    }

    @Test
    public void refreshAccessToken() {
        assertNull(provider.refreshAccessToken(new ImplicitResourceDetails(), new DefaultOAuth2RefreshToken(""), new DefaultAccessTokenRequest(
                Collections.emptyMap())));
    }

    @Test
    public void testImplicitResponseExtractor() throws IOException {
        assertNull(provider.getResponseExtractor().extractData(new MockClientHttpResponse(new byte[0], 200)));
    }

    @Test
    public void obtainAccessToken() {
        ImplicitResourceDetails details = new ImplicitResourceDetails();
        details.setScope(Set.of("openid").stream().toList());
        assertFalse(details.isClientOnly());
        assertNotNull(provider.obtainAccessToken(details, new DefaultAccessTokenRequest(Map.of("scope", new String[]{"x"}, "redirect_uri",
                new String[]{"x"}, "client_id", new String[]{"x"}))));
    }

    @Test
    public void obtainAccessTokenNoRecdirect() {
        assertThrows(IllegalStateException.class, () -> {
            ImplicitResourceDetails details = new ImplicitResourceDetails();
            details.setScope(Set.of("openid").stream().toList());
            assertFalse(details.isClientOnly());
            assertNotNull(provider.obtainAccessToken(details, new DefaultAccessTokenRequest(Map.of("scope", new String[]{"x"}, "client_id", new String[]{"x"}))));
        });
    }

    @Test
    public void testGetAccessTokenRequest() {
        AccessTokenRequest request = new DefaultAccessTokenRequest();
        resource.setClientId("foo");
        resource.setAccessTokenUri("http://localhost/oauth/authorize");
        resource.setPreEstablishedRedirectUri("https://anywhere.com");
        assertEquals("FOO", provider.obtainAccessToken(resource, request).getValue());
        assertEquals("foo", params.getFirst("client_id"));
        assertEquals("token", params.getFirst("response_type"));
        assertEquals("https://anywhere.com", params.getFirst("redirect_uri"));
    }

}
