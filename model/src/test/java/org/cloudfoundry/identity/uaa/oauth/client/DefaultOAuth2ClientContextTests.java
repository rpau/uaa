package org.cloudfoundry.identity.uaa.oauth.client;

import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class DefaultOAuth2ClientContextTests {

    @Test
    public void resetsState() {
        DefaultOAuth2ClientContext clientContext = new DefaultOAuth2ClientContext();
        clientContext.setPreservedState("state1", "some-state-1");
        clientContext.setPreservedState("state2", "some-state-2");
        clientContext.setPreservedState("state3", "some-state-3");
        assertNull(clientContext.removePreservedState("state1"));
        assertNull(clientContext.removePreservedState("state2"));
        assertEquals("some-state-3", clientContext.removePreservedState("state3"));
    }

    @Test
    public void init() {
        OAuth2AccessToken token = new DefaultOAuth2AccessToken("token");
        DefaultOAuth2ClientContext clientContext = new DefaultOAuth2ClientContext(token);
        clientContext.setPreservedState("state1", "some-state-1");
        assertNotNull(clientContext.removePreservedState("state1"));
        assertEquals(token, clientContext.getAccessToken());
        clientContext.setAccessToken(null);
        assertNotEquals(token, clientContext.getAccessToken());
    }
}
