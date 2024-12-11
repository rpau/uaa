package org.cloudfoundry.identity.uaa.oauth.common;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.util.Date;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
@ExtendWith(MockitoExtension.class)
public class OAuth2AccessTokenJackson2DeserializerTests extends BaseOAuth2AccessTokenJacksonTest {

    protected ObjectMapper mapper;

    @BeforeEach
    public void createObjectMapper() {
        mapper = new ObjectMapper();
    }

    @Test
    public void readValueNoRefresh() throws JsonGenerationException, JsonMappingException, IOException {
        accessToken.setRefreshToken(null);
        accessToken.setScope(null);
        OAuth2AccessToken actual = mapper.readValue(ACCESS_TOKEN_NOREFRESH, OAuth2AccessToken.class);
        assertTokenEquals(accessToken, actual);
    }

    @Test
    public void readValueWithRefresh() throws JsonGenerationException, JsonMappingException, IOException {
        accessToken.setScope(null);
        OAuth2AccessToken actual = mapper.readValue(ACCESS_TOKEN_NOSCOPE, OAuth2AccessToken.class);
        assertTokenEquals(accessToken, actual);
    }

    @Test
    public void readValueWithSingleScopes() throws JsonGenerationException, JsonMappingException, IOException {
        accessToken.getScope().remove(accessToken.getScope().iterator().next());
        OAuth2AccessToken actual = mapper.readValue(ACCESS_TOKEN_SINGLESCOPE, OAuth2AccessToken.class);
        assertTokenEquals(accessToken, actual);
    }

    @Test
    public void readValueWithEmptyStringScope() throws JsonGenerationException, JsonMappingException, IOException {
        accessToken.setScope(new HashSet<>());
        OAuth2AccessToken actual = mapper.readValue(ACCESS_TOKEN_EMPTYSCOPE, OAuth2AccessToken.class);
        assertTokenEquals(accessToken, actual);
    }

    @Test
    public void readValueWithBrokenExpiresIn() throws JsonGenerationException, JsonMappingException, IOException {
        accessToken.setScope(new HashSet<>());
        OAuth2AccessToken actual = mapper.readValue(ACCESS_TOKEN_BROKENEXPIRES, OAuth2AccessToken.class);
        assertTokenEquals(accessToken, actual);
    }

    @Test
    public void readValueWithMultiScopes() throws Exception {
        OAuth2AccessToken actual = mapper.readValue(ACCESS_TOKEN_MULTISCOPE, OAuth2AccessToken.class);
        assertTokenEquals(accessToken, actual);
    }

    @Test
    public void readValueWithArrayScopes() throws Exception {
        OAuth2AccessToken actual = mapper.readValue(ACCESS_TOKEN_ARRAYSCOPE, OAuth2AccessToken.class);
        assertTokenEquals(accessToken, actual);
    }

    @Test
    public void readValueWithMac() throws Exception {
        accessToken.setTokenType("mac");
        String encodedToken = ACCESS_TOKEN_MULTISCOPE.replace("bearer", accessToken.getTokenType());
        OAuth2AccessToken actual = mapper.readValue(encodedToken, OAuth2AccessToken.class);
        assertTokenEquals(accessToken, actual);
    }

    @Test
    public void readValueWithAdditionalInformation() throws Exception {
        OAuth2AccessToken actual = mapper.readValue(ACCESS_TOKEN_ADDITIONAL_INFO, OAuth2AccessToken.class);
        accessToken.setAdditionalInformation(additionalInformation);
        accessToken.setRefreshToken(null);
        accessToken.setScope(null);
        accessToken.setExpiration(null);
        assertTokenEquals(accessToken, actual);
    }

    @Test
    public void readValueWithZeroExpiresAsNotExpired() throws Exception {
        OAuth2AccessToken actual = mapper.readValue(ACCESS_TOKEN_ZERO_EXPIRES, OAuth2AccessToken.class);
        assertFalse(actual.isExpired(), "Token with expires_in:0 must be treated as not expired.");
    }

    private static void assertTokenEquals(OAuth2AccessToken expected, OAuth2AccessToken actual) {
        assertEquals(expected.getTokenType(), actual.getTokenType());
        assertEquals(expected.getValue(), actual.getValue());

        OAuth2RefreshToken expectedRefreshToken = expected.getRefreshToken();
        if (expectedRefreshToken == null) {
            assertNull(actual.getRefreshToken());
        } else {
            assertEquals(expectedRefreshToken.getValue(), actual.getRefreshToken().getValue());
        }
        assertEquals(expected.getScope(), actual.getScope());
        Date expectedExpiration = expected.getExpiration();
        if (expectedExpiration == null) {
            assertNull(actual.getExpiration());
        }
        assertEquals(expected.getAdditionalInformation(), actual.getAdditionalInformation());
    }
}