package org.cloudfoundry.identity.uaa.oauth.client.token.grant;

import org.cloudfoundry.identity.uaa.oauth.client.grant.ClientCredentialsAccessTokenProvider;
import org.cloudfoundry.identity.uaa.oauth.client.resource.ClientCredentialsResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2ProtectedResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.token.AccessTokenRequest;
import org.cloudfoundry.identity.uaa.oauth.token.DefaultAccessTokenRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ClientCredentialsAccessTokenProviderTest {

    private final MultiValueMap<String, String> params = new LinkedMultiValueMap<>();

    private final ClientCredentialsAccessTokenProvider provider = new ClientCredentialsAccessTokenProvider() {
        @Override
        protected OAuth2AccessToken retrieveToken(AccessTokenRequest request, OAuth2ProtectedResourceDetails resource,
                                                  MultiValueMap<String, String> form, HttpHeaders headers) {
            params.putAll(form);
            return new DefaultOAuth2AccessToken("FOO");
        }
    };

    @BeforeEach
    public void setUp() throws Exception {
    }

    @Test
    public void supportsResource() {
        assertTrue(provider.supportsResource(new ClientCredentialsResourceDetails()));
    }

    @Test
    public void supportsRefresh() {
        assertFalse(provider.supportsRefresh(new ClientCredentialsResourceDetails()));
    }

    @Test
    public void refreshAccessToken() {
        assertNull(provider.refreshAccessToken(new ClientCredentialsResourceDetails(), new DefaultOAuth2RefreshToken(""), new DefaultAccessTokenRequest(
                Collections.emptyMap())));
    }

    @Test
    public void obtainAccessToken() {
        ClientCredentialsResourceDetails details = new ClientCredentialsResourceDetails();
        details.setScope(Set.of("openid").stream().toList());
        assertTrue(details.isClientOnly());
        assertNotNull(provider.obtainAccessToken(details, new DefaultAccessTokenRequest(Map.of("scope", new String[]{"x"}))));
    }
}