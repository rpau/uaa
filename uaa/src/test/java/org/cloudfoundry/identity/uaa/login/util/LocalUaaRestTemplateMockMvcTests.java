package org.cloudfoundry.identity.uaa.login.util;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.message.LocalUaaRestTemplate;
import org.cloudfoundry.identity.uaa.oauth.client.DefaultOAuth2ClientContext;
import org.cloudfoundry.identity.uaa.oauth.client.OAuth2RestTemplate;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.util.ReflectionUtils;

import java.lang.reflect.Method;
import java.net.URI;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.startsWith;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DefaultTestContext
class LocalUaaRestTemplateMockMvcTests {

    @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
    @Autowired
    private LocalUaaRestTemplate localUaaRestTemplate;

    @Test
    void localUaaRestTemplateAcquireToken() {
        OAuth2AccessToken token = localUaaRestTemplate.acquireAccessToken(new DefaultOAuth2ClientContext());
        assertTrue(token.getScope().contains("oauth.login"), "Scopes should contain oauth.login");
        assertTrue(token.getScope().contains("notifications.write"), "Scopes should contain notifications.write");
        assertTrue(token.getScope().contains("critical_notifications.write"), "Scopes should contain critical_notifications.write");
    }

    @Test
    void uaaRestTemplateContainsBearerHeader() throws Exception {
        OAuth2AccessToken token = localUaaRestTemplate.acquireAccessToken(localUaaRestTemplate.getOAuth2ClientContext());
        Method createRequest = OAuth2RestTemplate.class.getDeclaredMethod("createRequest", URI.class, HttpMethod.class);
        ReflectionUtils.makeAccessible(createRequest);
        ClientHttpRequest request = (ClientHttpRequest) createRequest.invoke(localUaaRestTemplate, new URI("http://localhost/oauth/token"), HttpMethod.POST);
        assertEquals(1, request.getHeaders().get("Authorization").size(), "authorization bearer header should be present");
        assertNotNull(request.getHeaders().get("Authorization").get(0), "authorization bearer header should be present");
        assertThat(request.getHeaders().get("Authorization").get(0).toLowerCase(), startsWith("bearer "));
        assertThat(request.getHeaders().get("Authorization").get(0), endsWith(token.getValue()));
    }
}
