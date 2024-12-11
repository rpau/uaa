/*
 * *****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.integration;

import org.cloudfoundry.identity.uaa.ServerRunningExtension;
import org.cloudfoundry.identity.uaa.integration.util.IntegrationTestUtils;
import org.cloudfoundry.identity.uaa.oauth.client.resource.AuthorizationCodeResourceDetails;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.test.TestAccountExtension;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.Map;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author Dave Syer
 * @author Luke Taylor
 */
public class AuthorizationCodeGrantIntegrationTests {

    @RegisterExtension
    private static final ServerRunningExtension serverRunning = ServerRunningExtension.connect();

    private static final UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @RegisterExtension
    private static final TestAccountExtension testAccountSetup = TestAccountExtension.standard(serverRunning, testAccounts);

    @Test
    void testSuccessfulAuthorizationCodeFlow() {
        testSuccessfulAuthorizationCodeFlow_Internal();
        testSuccessfulAuthorizationCodeFlow_Internal();
    }

    @Test
    public void testSuccessfulAuthorizationCodeFlowWithPkceS256() throws Exception {
        testAuthorizationCodeFlowWithPkce_Internal(UaaTestAccounts.CODE_CHALLENGE,
                UaaTestAccounts.CODE_CHALLENGE_METHOD_S256, UaaTestAccounts.CODE_VERIFIER);
        testAuthorizationCodeFlowWithPkce_Internal(UaaTestAccounts.CODE_CHALLENGE,
                UaaTestAccounts.CODE_CHALLENGE_METHOD_S256, UaaTestAccounts.CODE_VERIFIER);
    }

    @Test
    public void testSuccessfulAuthorizationCodeFlowWithPkcePlain() throws Exception {
        testAuthorizationCodeFlowWithPkce_Internal(UaaTestAccounts.CODE_CHALLENGE, "plain", UaaTestAccounts.CODE_CHALLENGE);
        testAuthorizationCodeFlowWithPkce_Internal(UaaTestAccounts.CODE_CHALLENGE, "plain", UaaTestAccounts.CODE_CHALLENGE);
    }

    @Test
    public void testPkcePlainWithWrongCodeVerifier() throws Exception {
        ResponseEntity<Map> tokenResponse = doAuthorizeAndTokenRequest(UaaTestAccounts.CODE_CHALLENGE, "plain", UaaTestAccounts.CODE_VERIFIER);
        assertEquals(HttpStatus.BAD_REQUEST, tokenResponse.getStatusCode());
        Map<String, String> body = tokenResponse.getBody();
        assertThat(body.get("error"), containsString("invalid_grant"));
        assertThat(body.get("error_description"), containsString("Invalid code verifier"));
    }

    @Test
    public void testPkceS256WithWrongCodeVerifier() throws Exception {
        ResponseEntity<Map> tokenResponse = doAuthorizeAndTokenRequest(UaaTestAccounts.CODE_CHALLENGE, UaaTestAccounts.CODE_CHALLENGE_METHOD_S256, UaaTestAccounts.CODE_CHALLENGE);
        assertEquals(HttpStatus.BAD_REQUEST, tokenResponse.getStatusCode());
        Map<String, String> body = tokenResponse.getBody();
        assertThat(body.get("error"), containsString("invalid_grant"));
        assertThat(body.get("error_description"), containsString("Invalid code verifier"));
    }

    @Test
    public void testMissingCodeChallenge() throws Exception {
        ResponseEntity<Map> tokenResponse = doAuthorizeAndTokenRequest("", UaaTestAccounts.CODE_CHALLENGE_METHOD_S256, UaaTestAccounts.CODE_VERIFIER);
        assertEquals(HttpStatus.BAD_REQUEST, tokenResponse.getStatusCode());
        Map<String, String> body = tokenResponse.getBody();
        assertThat(body.get("error"), containsString("invalid_grant"));
        assertThat(body.get("error_description"), containsString("PKCE error: Code verifier not required for this authorization code."));
    }

    @Test
    public void testMissingCodeVerifier() throws Exception {
        ResponseEntity<Map> tokenResponse = doAuthorizeAndTokenRequest(UaaTestAccounts.CODE_CHALLENGE, UaaTestAccounts.CODE_CHALLENGE_METHOD_S256, "");
        assertEquals(HttpStatus.BAD_REQUEST, tokenResponse.getStatusCode());
        Map<String, String> body = tokenResponse.getBody();
        assertThat(body.get("error"), containsString("invalid_grant"));
        assertThat(body.get("error_description"), containsString("PKCE error: Code verifier must be provided for this authorization code."));
    }

    @Test
    public void testInvalidCodeChallenge() throws Exception {
        AuthorizationCodeResourceDetails resource = testAccounts.getDefaultAuthorizationCodeResource();
        String responseLocation = IntegrationTestUtils.getAuthorizationResponse(serverRunning,
                resource.getClientId(),
                testAccounts.getUserName(),
                testAccounts.getPassword(),
                resource.getPreEstablishedRedirectUri(),
                "ShortCodeChallenge",
                UaaTestAccounts.CODE_CHALLENGE_METHOD_S256);
        assertThat(responseLocation, containsString("Code challenge length must between 43 and 128 and use only [A-Z],[a-z],[0-9],_,.,-,~ characters."));
    }

    @Test
    public void testInvalidCodeVerifier() throws Exception {
        AuthorizationCodeResourceDetails resource = testAccounts.getDefaultAuthorizationCodeResource();
        ResponseEntity<Map> tokenResponse = IntegrationTestUtils.getTokens(serverRunning,
                resource.getClientId(),
                resource.getClientSecret(),
                resource.getPreEstablishedRedirectUri(),
                "invalidCodeVerifier",
                "authorizationCode");
        assertEquals(HttpStatus.BAD_REQUEST, tokenResponse.getStatusCode());
        Map<String, String> body = tokenResponse.getBody();
        assertThat(body.get("error"), containsString("invalid_request"));
        assertThat(body.get("error_description"), containsString("Code verifier length must"));
    }

    @Test
    public void testUnsupportedCodeChallengeMethod() throws Exception {
        AuthorizationCodeResourceDetails resource = testAccounts.getDefaultAuthorizationCodeResource();
        String responseLocation = IntegrationTestUtils.getAuthorizationResponse(serverRunning,
                resource.getClientId(),
                testAccounts.getUserName(),
                testAccounts.getPassword(),
                resource.getPreEstablishedRedirectUri(),
                UaaTestAccounts.CODE_CHALLENGE,
                "UnsupportedCodeChallengeMethod");
        assertThat(responseLocation, containsString("Unsupported code challenge method."));
    }

    @Test
    public void testZoneDoesNotExist() {
        ServerRunningExtension.UriBuilder builder = serverRunning.buildUri(serverRunning.getAuthorizationUri().replace("localhost", "testzonedoesnotexist.localhost"))
                .queryParam("response_type", "code")
                .queryParam("state", "mystateid")
                .queryParam("client_id", "clientId")
                .queryParam("redirect_uri", "http://localhost:8080/uaa");

        URI uri = builder.build();

        ResponseEntity<Void> result =
                serverRunning.createRestTemplate().exchange(
                        uri.toString(),
                        HttpMethod.GET,
                        new HttpEntity<>(null, new HttpHeaders()),
                        Void.class
                );
        assertEquals(HttpStatus.NOT_FOUND, result.getStatusCode());
    }

    @Test
    public void testZoneInactive() {
        RestTemplate identityClient = IntegrationTestUtils
                .getClientCredentialsTemplate(IntegrationTestUtils.getClientCredentialsResource(serverRunning.getBaseUrl(),
                        new String[]{"zones.write", "zones.read", "scim.zones"}, "identity", "identitysecret"));
        IntegrationTestUtils.createInactiveIdentityZone(identityClient, "http://localhost:8080/uaa");
        ServerRunningExtension.UriBuilder builder = serverRunning.buildUri(serverRunning.getAuthorizationUri().replace("localhost", "testzoneinactive.localhost"))
                .queryParam("response_type", "code")
                .queryParam("state", "mystateid")
                .queryParam("client_id", "clientId")
                .queryParam("redirect_uri", "http://localhost:8080/uaa");

        URI uri = builder.build();

        ResponseEntity<Void> result =
                serverRunning.createRestTemplate().exchange(
                        uri.toString(),
                        HttpMethod.GET,
                        new HttpEntity<>(null, new HttpHeaders()),
                        Void.class
                );
        assertEquals(HttpStatus.NOT_FOUND, result.getStatusCode());
    }

    @Test
    public void testAuthorizationRequestWithoutRedirectUri() {

        Map<String, String> body = IntegrationTestUtils.getAuthorizationCodeTokenMap(serverRunning,
                "login",
                "loginsecret",
                testAccounts.getUserName(),
                testAccounts.getPassword(),
                null,
                null,
                null,
                null,
                false);

        assertNotNull(body.get("access_token"), "Token not received");

        try {
            IntegrationTestUtils.getAuthorizationCodeTokenMap(serverRunning, "app", "appclientsecret",
                    testAccounts.getUserName(), testAccounts.getPassword(),
                    null, null, null, null, false);
        } catch (AssertionError error) {
            // expected
            return;
        }
        Assertions.fail("Token retrival not allowed");
    }

    public void testSuccessfulAuthorizationCodeFlow_Internal() {
        AuthorizationCodeResourceDetails resource = testAccounts.getDefaultAuthorizationCodeResource();

        Map<String, String> body = IntegrationTestUtils.getAuthorizationCodeTokenMap(serverRunning,
                testAccounts,
                resource.getClientId(),
                resource.getClientSecret(),
                testAccounts.getUserName(),
                testAccounts.getPassword());
        Jwt token = JwtHelper.decode(body.get("access_token"));
        assertTrue(token.getClaims().contains("\"aud\""), "Wrong claims: " + token.getClaims());
        assertTrue(token.getClaims().contains("\"user_id\""), "Wrong claims: " + token.getClaims());
    }

    private void testAuthorizationCodeFlowWithPkce_Internal(String codeChallenge, String codeChallengeMethod, String codeVerifier) throws Exception {

        ResponseEntity<Map> tokenResponse = doAuthorizeAndTokenRequest(codeChallenge, codeChallengeMethod, codeVerifier);
        assertEquals(HttpStatus.OK, tokenResponse.getStatusCode());
        Map<String, String> body = tokenResponse.getBody();
        Jwt token = JwtHelper.decode(body.get("access_token"));
        assertTrue(token.getClaims().contains("\"aud\""), "Wrong claims: " + token.getClaims());
        assertTrue(token.getClaims().contains("\"user_id\""), "Wrong claims: " + token.getClaims());
        IntegrationTestUtils.callCheckToken(serverRunning,
                body.get("access_token"),
                testAccounts.getDefaultAuthorizationCodeResource().getClientId(),
                testAccounts.getDefaultAuthorizationCodeResource().getClientSecret());
    }

    private ResponseEntity<Map> doAuthorizeAndTokenRequest(String codeChallenge, String codeChallengeMethod, String codeVerifier) throws Exception {
        AuthorizationCodeResourceDetails resource = testAccounts.getDefaultAuthorizationCodeResource();
        String authorizationResponse = IntegrationTestUtils.getAuthorizationResponse(serverRunning,
                resource.getClientId(),
                testAccounts.getUserName(),
                testAccounts.getPassword(),
                resource.getPreEstablishedRedirectUri(),
                codeChallenge,
                codeChallengeMethod);
        String authorizationCode = authorizationResponse.split("code=")[1].split("&")[0];
        return IntegrationTestUtils.getTokens(serverRunning,
                resource.getClientId(),
                resource.getClientSecret(),
                resource.getPreEstablishedRedirectUri(),
                codeVerifier,
                authorizationCode);
    }
}
