package org.cloudfoundry.identity.uaa.integration.feature;

import org.cloudfoundry.identity.uaa.oauth.client.test.TestAccounts;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.openqa.selenium.WebDriver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestOperations;

import java.util.Collections;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringJUnitConfig(classes = DefaultIntegrationTestConfig.class)
class UserTokenGrantIT {

    @Autowired
    @RegisterExtension
    private IntegrationTestExtension integrationTestExtension;

    @Autowired
    WebDriver webDriver;

    @Value("${integration.test.base_url}")
    String baseUrl;

    @Value("${integration.test.app_url}")
    String appUrl;

    @Autowired
    RestOperations restOperations;

    @Autowired
    TestClient testClient;

    @Autowired
    TestAccounts testAccounts;

    final String user_token_id = "oauth_showcase_user_token";
    final String user_token_secret = "secret";
    final String user_token_public_id = "oauth_showcase_user_token_public";
    final String empty_string = "";

    @AfterEach
    void logout_and_clear_cookies() {
        try {
            webDriver.get(baseUrl + "/logout.do");
        } catch (org.openqa.selenium.TimeoutException x) {
            //try again - this should not be happening - 20 second timeouts
            webDriver.get(baseUrl + "/logout.do");
        }
        webDriver.get(appUrl + "/j_spring_security_logout");
        webDriver.manage().deleteAllCookies();
    }

    @Test
    void exchangeFromConfidentialClientWithCfClientWithEmptySecret() {
        // Given Create password token from confidential client
        String token = getPasswordGrantToken(user_token_id, user_token_secret);

        // When do user_token grant flow using public cf client (public, because of empty secret)
        String newToken = doUserTokenGrant("cf", token, HttpStatus.OK);

        // Then validation expected result
        assertThat(newToken).isNotNull();
        checkRefreshToken(newToken);
    }

    @Test
    void exchangeFromConfidentialClientWithConfidentialClient() {
        // Given Create password token from confidential client
        String token = getPasswordGrantToken(user_token_id, user_token_secret);

        // When do user_token grant flow using confidential oauth_showcase_user_token client
        String newToken = doUserTokenGrant(user_token_id, token, HttpStatus.OK);

        // Then validation expected result
        checkRefreshToken(newToken);
    }

    @Test
    void exchangeFromPublicClientWithPublicClient() {
        // Given Create password token from public client
        String token = getPasswordGrantToken(user_token_public_id, empty_string);

        // When do user_token grant flow using public client
        String newToken = doUserTokenGrant(user_token_public_id, token, HttpStatus.OK);

        // Then validation expected result
        checkRefreshToken(newToken);
    }

    @Test
    void exchangeFromPublicClientWithConfidentialClient() {
        // Given Create password token from public client
        String token = getPasswordGrantToken(user_token_public_id, empty_string);

        // When do user_token grant flow using confidential oauth_showcase_user_token client
        String newToken = doUserTokenGrant(user_token_id, token, HttpStatus.OK);

        // Then validation expected result
        checkRefreshToken(newToken);
    }

    @Test
    void exchangeFromConfidentialClientWithAdminClientExpectUnauthorized() {
        // Given Create password token from public client
        String token = getPasswordGrantToken(user_token_id, user_token_secret);

        // When do user_token grant flow using admin client
        doUserTokenGrant("admin", token, HttpStatus.UNAUTHORIZED);
    }

    private String getPasswordGrantToken(String clientId, String clientSecret) {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        headers.add("Authorization", ((UaaTestAccounts) testAccounts).getAuthorizationHeader(clientId, clientSecret));

        LinkedMultiValueMap<String, String> postBody = new LinkedMultiValueMap<>();
        postBody.add("grant_type", "password");
        postBody.add("username", testAccounts.getUserName());
        postBody.add("password", testAccounts.getPassword());

        ResponseEntity<Map> responseEntity = restOperations.exchange(baseUrl + "/oauth/token", HttpMethod.POST, new HttpEntity<>(postBody, headers),
                Map.class);

        assertThat(responseEntity.getStatusCode()).isEqualTo(HttpStatus.OK);
        return (String) responseEntity.getBody().get("access_token");
    }

    private String doUserTokenGrant(String clientId, String token, HttpStatus expectedStatus) {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.add("Authorization", " Bearer " + token);

        LinkedMultiValueMap<String, String> postBody = new LinkedMultiValueMap<>();
        postBody.add("client_id", clientId);
        postBody.add("token_format", "jwt");
        postBody.add("response_type", "token");
        postBody.add("grant_type", "user_token");
        ResponseEntity<Map> responseEntity = null;
        HttpStatus responseStatus;

        try {
            responseEntity = restOperations.exchange(baseUrl + "/oauth/token", HttpMethod.POST, new HttpEntity<>(postBody, headers), Map.class);
            responseStatus = responseEntity.getStatusCode();
        } catch (HttpClientErrorException clientErrorException) {
            responseStatus = clientErrorException.getStatusCode();
        }
        assertThat(responseStatus).isEqualTo(expectedStatus);

        if (expectedStatus == HttpStatus.OK) {
            Map<String, Object> params = responseEntity.getBody();
            return (String) params.get("refresh_token");
        } else {
            return null;
        }
    }

    private void checkRefreshToken(String token) {
        assertThat(token).isNotNull();
        assertThat(token.length()).isEqualTo(34);
        assertThat(token.endsWith("-r")).isTrue();
    }
}
