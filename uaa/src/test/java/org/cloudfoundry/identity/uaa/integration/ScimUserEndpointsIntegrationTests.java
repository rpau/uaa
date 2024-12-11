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
import org.cloudfoundry.identity.uaa.oauth.client.http.OAuth2ErrorHandler;
import org.cloudfoundry.identity.uaa.oauth.client.test.OAuth2ContextConfiguration;
import org.cloudfoundry.identity.uaa.oauth.client.test.OAuth2ContextExtension;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestAccountExtension;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@OAuth2ContextConfiguration(OAuth2ContextConfiguration.ClientCredentials.class)
public class ScimUserEndpointsIntegrationTests {

    private final String JOEL = "joel_" + new RandomValueStringGenerator().generate().toLowerCase();

    private final String JOE = "JOE_" + new RandomValueStringGenerator().generate().toLowerCase();

    private final String DELETE_ME = "deleteme_" + new RandomValueStringGenerator().generate().toLowerCase();

    private final String userEndpoint = "/Users";

    private final String usersEndpoint = "/Users";

    private static final int NUM_DEFAULT_GROUPS_ON_STARTUP = 14;

    @RegisterExtension
    private static final ServerRunningExtension serverRunning = ServerRunningExtension.connect();

    private static final UaaTestAccounts testAccounts = UaaTestAccounts.standard(serverRunning);

    @RegisterExtension
    private static final TestAccountExtension testAccountSetup = TestAccountExtension.standard(serverRunning, testAccounts);

    @RegisterExtension
    private static final OAuth2ContextExtension context = OAuth2ContextExtension.withTestAccounts(serverRunning, testAccountSetup);

    private RestTemplate client;
    private List<ScimUser> scimUsers;

    @BeforeEach
    public void createRestTemplate() {
        client = (RestTemplate) serverRunning.getRestTemplate();
        client.setErrorHandler(new OAuth2ErrorHandler(context.getResource()) {
            // Pass errors through in response entity for status code analysis
            @Override
            public boolean hasError(ClientHttpResponse response) {
                return false;
            }

            @Override
            public void handleError(ClientHttpResponse response) {
            }
        });
    }

    @SuppressWarnings("rawtypes")
    private ResponseEntity<Map> deleteUser(String id, int version) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("If-Match", "\"" + version + "\"");
        return client.exchange(serverRunning.getUrl(userEndpoint + "/{id}"), HttpMethod.DELETE, new HttpEntity<Void>(
                headers), Map.class, id);
    }

    private ResponseEntity<ScimUser> createUser(String username, String firstName, String lastName, String email) {
        ScimUser user = new ScimUser();
        user.setUserName(username);
        user.setPassword("password");
        user.setName(new ScimUser.Name(firstName, lastName));
        user.addEmail(email);

        return client.postForEntity(serverRunning.getUrl(userEndpoint), user, ScimUser.class);
    }

    private ResponseEntity<ScimUser> createUser(String username, String firstName, String lastName,
                                                String email, boolean verified) {
        ScimUser user = new ScimUser();
        user.setPassword("password");
        user.setUserName(username);
        user.setName(new ScimUser.Name(firstName, lastName));
        user.addEmail(email);
        user.setVerified(verified);

        return client.postForEntity(serverRunning.getUrl(userEndpoint), user, ScimUser.class);
    }

    // curl -v -H "Content-Type: application/json" -H "Accept: application/json"
    // --data
    // "{\"userName\":\"joe\",\"schemas\":[\"urn:scim:schemas:core:1.0\"]}"
    // http://localhost:8080/uaa/User
    @Test
    public void createUserSucceeds() {
        ResponseEntity<ScimUser> response = createUser(JOE, "Joe", "User", "joe@blah.com");
        ScimUser joe1 = response.getBody();
        assertEquals(JOE, joe1.getUserName());

        // Check we can GET the user
        ScimUser joe2 = client.getForObject(serverRunning.getUrl(userEndpoint + "/{id}"), ScimUser.class, joe1.getId());

        assertEquals(joe1.getId(), joe2.getId());
        assertTrue(joe2.isVerified());
    }

    // curl -v -H "Content-Type: application/json" -H "Accept: application/json"
    // --data
    // "{\"userName\":\"joe\",\"schemas\":[\"urn:scim:schemas:core:1.0\"]}"
    // http://localhost:8080/uaa/User
    @Test
    public void createUserSucceedsWithVerifiedIsFalse() {
        ResponseEntity<ScimUser> response = createUser(JOE, "Joe", "User", "joe@blah.com", false);
        ScimUser joe1 = response.getBody();
        assertEquals(JOE, joe1.getUserName());

        // Check we can GET the user
        ScimUser joe2 = client.getForObject(serverRunning.getUrl(userEndpoint + "/{id}"), ScimUser.class, joe1.getId());

        assertEquals(joe1.getId(), joe2.getId());
        assertFalse(joe2.isVerified());
    }

    // curl -v -H "Content-Type: application/json" -H "Accept: application/json"
    // --data
    // "{\"userName\":\"joe\",\"schemas\":[\"urn:scim:schemas:core:1.0\"]}"
    // http://localhost:8080/uaa/User
    @Test
    public void verifyUser() {
        ResponseEntity<ScimUser> response = createUser(JOE, "Joe", "User", "joe@blah.com", false);
        ScimUser joe1 = response.getBody();
        assertEquals(JOE, joe1.getUserName());
        // Check we can GET the user
        ScimUser joe2 = client.getForObject(serverRunning.getUrl(userEndpoint + "/{id}"), ScimUser.class, joe1.getId());
        assertEquals(joe1.getId(), joe2.getId());
        assertFalse(joe2.isVerified());
        ScimUser joe3 = client.getForObject(serverRunning.getUrl(userEndpoint + "/{id}/verify"), ScimUser.class,
                joe1.getId());
        assertTrue(joe3.isVerified());
        ScimUser joe4 = client.getForObject(serverRunning.getUrl(userEndpoint + "/{id}"), ScimUser.class, joe1.getId());
        assertTrue(joe4.isVerified());
    }

    // curl -v -H "Content-Type: application/json" -H "Accept: application/json"
    // --data
    // "{\"userName\":\"joe\",\"schemas\":[\"urn:scim:schemas:core:1.0\"]}"
    // http://localhost:8080/uaa/User
    @Test
    public void verifyUserNotFound() {
        HttpHeaders headers = new HttpHeaders();
        ResponseEntity<Map> response = client.exchange(serverRunning.getUrl(userEndpoint + "/{id}/verify"),
                HttpMethod.GET,
                new HttpEntity<Void>(headers),
                Map.class,
                "this-user-id-doesnt-exist");

        @SuppressWarnings("unchecked")
        Map<String, String> error = response.getBody();
        assertEquals("scim_resource_not_found", error.get("error"));
        assertEquals("User this-user-id-doesnt-exist does not exist", error.get("message"));
    }

    @Test
    public void createUserWithNoEmailFails() {
        ScimUser user = new ScimUser();
        user.setPassword("password");
        user.setUserName("dave");
        user.setName(new ScimUser.Name("Dave", "Syer"));

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = client.postForEntity(serverRunning.getUrl(userEndpoint), user, Map.class);
        @SuppressWarnings("unchecked")
        Map<String, String> error = response.getBody();

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("invalid_scim_resource", error.get("error"));
    }

    @Test
    public void getUserHasEtag() {
        ResponseEntity<ScimUser> response = createUser(JOE, "Joe", "User", "joe@blah.com");
        ScimUser joe = response.getBody();
        assertEquals(JOE, joe.getUserName());

        // Check we can GET the user
        ResponseEntity<ScimUser> result = client.getForEntity(serverRunning.getUrl(userEndpoint + "/{id}"),
                ScimUser.class, joe.getId());
        assertEquals("\"" + joe.getVersion() + "\"", result.getHeaders().getFirst("ETag"));
    }

    // curl -v -H "Content-Type: application/json" -X PUT -H
    // "Accept: application/json" --data
    // "{\"userName\":\"joe\",\"schemas\":[\"urn:scim:schemas:core:1.0\"]}"
    // http://localhost:8080/uaa/User
    @Test
    public void updateUserSucceeds() {
        ResponseEntity<ScimUser> response = createUser(JOE, "Joe", "User", "joe@blah.com");
        ScimUser joe = response.getBody();
        assertEquals(JOE, joe.getUserName());

        joe.setName(new ScimUser.Name("Joe", "Bloggs"));

        HttpHeaders headers = new HttpHeaders();
        headers.add("If-Match", "\"" + joe.getVersion() + "\"");
        response = client.exchange(serverRunning.getUrl(userEndpoint) + "/{id}", HttpMethod.PUT,
                new HttpEntity<ScimUser>(joe, headers), ScimUser.class, joe.getId());
        ScimUser joe1 = response.getBody();
        assertEquals(JOE, joe1.getUserName());

        assertEquals(joe.getId(), joe1.getId());
    }

    @Test
    public void updateUserNameSucceeds() {
        ResponseEntity<ScimUser> response = createUser(JOE, "Joe", "User", "joe@blah.com");
        ScimUser joe = response.getBody();
        assertEquals(JOE, joe.getUserName());

        joe.setUserName(JOE + "new");

        HttpHeaders headers = new HttpHeaders();
        headers.add("If-Match", "\"" + joe.getVersion() + "\"");
        response = client.exchange(serverRunning.getUrl(userEndpoint) + "/{id}", HttpMethod.PUT,
                new HttpEntity<ScimUser>(joe, headers), ScimUser.class, joe.getId());
        ScimUser joe1 = response.getBody();
        assertEquals(JOE + "new", joe1.getUserName());

        assertEquals(joe.getId(), joe1.getId());
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    @Test
    public void updateUserWithBadAttributeFails() {

        ResponseEntity<ScimUser> created = createUser(JOE, "Joe", "User", "joe@blah.com");
        ScimUser joe = created.getBody();
        HttpHeaders headers = new HttpHeaders();
        headers.add("If-Match", "\"" + joe.getVersion() + "\"");
        Map<String, Object> map = new HashMap<>(JsonUtils.readValue(JsonUtils.writeValueAsString(joe),
                Map.class));
        map.put("nottheusername", JOE + "0");
        ResponseEntity<Map> response = client.exchange(serverRunning.getUrl(userEndpoint) + "/{id}", HttpMethod.PUT,
                new HttpEntity<Map>(map, headers), Map.class, joe.getId());
        Map<String, Object> joe1 = response.getBody();
        assertTrue(((String) joe1.get("message")).toLowerCase()
                .contains("unrecognized field"), "Wrong message: " + joe1);
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    @Test
    public void testJsonCaseInsensitivity() {

        ResponseEntity<ScimUser> created = createUser(JOE, "Joe", "User", "joe@blah.com");
        ScimUser joe = created.getBody();
        HttpHeaders headers = new HttpHeaders();
        headers.add("If-Match", "\"" + joe.getVersion() + "\"");
        Map<String, Object> map = new HashMap<>(JsonUtils.readValue(JsonUtils.writeValueAsString(joe),
                Map.class));
        map.put("username", JOE + "0");
        map.remove("userName");
        ResponseEntity<ScimUser> response = client.exchange(serverRunning.getUrl(userEndpoint) + "/{id}",
                HttpMethod.PUT,
                new HttpEntity<Map>(map, headers), ScimUser.class, joe.getId());
        ScimUser joe1 = response.getBody();
        assertEquals(JOE + "0", joe1.getUserName());
    }

    @Test
    public void updateUserWithNewAuthoritiesSucceeds() {
        ResponseEntity<ScimUser> response = createUser(JOE, "Joe", "User", "joe@blah.com");
        ScimUser joe = response.getBody();
        assertEquals(JOE, joe.getUserName());

        joe.setUserType("admin");

        HttpHeaders headers = new HttpHeaders();
        headers.add("If-Match", "\"" + joe.getVersion() + "\"");
        response = client.exchange(serverRunning.getUrl(userEndpoint) + "/{id}", HttpMethod.PUT,
                new HttpEntity<ScimUser>(joe, headers), ScimUser.class, joe.getId());
        ScimUser joe1 = response.getBody();
        assertEquals(JOE, joe1.getUserName());

        assertEquals(joe.getId(), joe1.getId());
        assertNull(joe1.getUserType()); // check that authorities was not updated
    }

    @Test
    public void updateUserGroupsDoesNothing() {
        ResponseEntity<ScimUser> response = createUser(JOE, "Joe", "User", "joe@blah.com");
        ScimUser joe = response.getBody();
        assertEquals(JOE, joe.getUserName());
        assertEquals(NUM_DEFAULT_GROUPS_ON_STARTUP, joe.getGroups().size());

        joe.setGroups(Collections.singletonList(new ScimUser.Group(UUID.randomUUID().toString(), "uaa.admin")));

        HttpHeaders headers = new HttpHeaders();
        headers.add("If-Match", "\"" + joe.getVersion() + "\"");
        response = client.exchange(serverRunning.getUrl(userEndpoint) + "/{id}", HttpMethod.PUT,
                new HttpEntity<ScimUser>(joe, headers), ScimUser.class, joe.getId());
        ScimUser joe1 = response.getBody();
        assertEquals(JOE, joe1.getUserName());

        assertEquals(joe.getId(), joe1.getId());
        assertEquals(NUM_DEFAULT_GROUPS_ON_STARTUP, joe1.getGroups().size());
    }

    // curl -v -H "Content-Type: application/json" -H "Accept: application/json"
    // -H 'If-Match: "0"' --data
    // "{\"userName\":\"joe\",\"schemas\":[\"urn:scim:schemas:core:1.0\"]}"
    // http://localhost:8080/uaa/User
    @Test
    public void createUserTwiceFails() {
        ScimUser user = new ScimUser();
        user.setPassword("password");
        user.setUserName(JOEL);
        user.setName(new ScimUser.Name("Joel", "D'sa"));
        user.addEmail("joel@blah.com");

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = client.postForEntity(serverRunning.getUrl(userEndpoint), user, Map.class);
        @SuppressWarnings("unchecked")
        Map<String, String> joel = response.getBody();
        assertEquals(JOEL, joel.get("userName"));

        response = client.postForEntity(serverRunning.getUrl(userEndpoint), user, Map.class);
        @SuppressWarnings("unchecked")
        Map<String, String> error = response.getBody();

        assertEquals("scim_resource_already_exists", error.get("error"));

    }

    @Test
    public void createUserWithJustACaseChangeFails() {
        String userName = JOEL;
        String userNameDifferenceCase = userName.toUpperCase();

        ScimUser user = new ScimUser();
        user.setPassword("password");
        user.setUserName(userName);
        user.setName(new ScimUser.Name("Joel", "D'sa"));
        user.addEmail("joel@blah.com");

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = client.postForEntity(serverRunning.getUrl(userEndpoint), user, Map.class);
        @SuppressWarnings("unchecked")
        Map<String, String> joel = response.getBody();
        assertEquals(JOEL, joel.get("userName"));

        ScimUser userDifferentCase = new ScimUser();
        userDifferentCase.setPassword("password");
        userDifferentCase.setUserName(userNameDifferenceCase);
        userDifferentCase.setName(new ScimUser.Name("Joel", "D'sa"));
        userDifferentCase.addEmail("joel@blah.com");

        response = client.postForEntity(serverRunning.getUrl(userEndpoint), userDifferentCase, Map.class);
        @SuppressWarnings("unchecked")
        Map<String, String> error = response.getBody();

        assertEquals("scim_resource_already_exists", error.get("error"));

    }

    // curl -v -H "Content-Type: application/json" -H "Accept: application/json"
    // -X DELETE
    // -H "If-Match: 0" http://localhost:8080/uaa/User/joel
    @Test
    public void deleteUserWithWrongIdFails() {
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = deleteUser("9999", 0);
        @SuppressWarnings("unchecked")
        Map<String, String> error = response.getBody();
        assertEquals("scim_resource_not_found", error.get("error"));
        assertEquals("User 9999 does not exist", error.get("message"));
    }

    // curl -v -H "Content-Type: application/json" -H "Accept: application/json"
    // -X DELETE
    // http://localhost:8080/uaa/User/joel
    @Test
    public void deleteUserWithNoEtagSucceeds() {
        ScimUser deleteMe = createUser(DELETE_ME, "Delete", "Me", "deleteme@blah.com").getBody();

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = client.exchange(serverRunning.getUrl(userEndpoint + "/{id}"), HttpMethod.DELETE,
                new HttpEntity<Void>((Void) null), Map.class, deleteMe.getId());
        assertEquals(HttpStatus.OK, response.getStatusCode());
    }

    @Test
    public void getReturnsNotFoundForNonExistentUser() {
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = client.exchange(serverRunning.getUrl(userEndpoint + "/{id}"), HttpMethod.GET,
                new HttpEntity<Void>((Void) null), Map.class, "9999");
        @SuppressWarnings("unchecked")
        Map<String, String> error = response.getBody();
        assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
        assertEquals("scim_resource_not_found", error.get("error"));
        assertEquals("User 9999 does not exist", error.get("message"));
    }

    @Test
    public void findUsers() {
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.getForObject(usersEndpoint, Map.class);

        @SuppressWarnings("rawtypes")
        Map results = response.getBody();
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue((Integer) results.get("totalResults") > 0, "There should be more than zero users");
        assertTrue(!((Collection<?>) results.get("resources")).isEmpty(), "There should be some resources");
        @SuppressWarnings("rawtypes")
        Map firstUser = (Map) ((List) results.get("resources")).get(0);
        // [cfid-111] All attributes should be returned if no attributes
        // supplied in query
        assertTrue(firstUser.containsKey("id"));
        assertTrue(firstUser.containsKey("userName"));
        assertTrue(firstUser.containsKey("name"));
        assertTrue(firstUser.containsKey("emails"));
        assertTrue(firstUser.containsKey("groups"));
    }

    @Test
    @SuppressWarnings({"rawtypes", "unchecked"})
    public void findUsersWithAttributes() {
        ResponseEntity<Map> response = serverRunning.getForObject(usersEndpoint + "?attributes=id,userName", Map.class);
        Map<String, Object> results = response.getBody();
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue((Integer) results.get("totalResults") > 0, "There should be more than zero users");
        Map firstUser = (Map) ((List) results.get("resources")).get(0);
        // All attributes should be returned if no attributes supplied in query
        assertTrue(firstUser.containsKey("id"));
        assertTrue(firstUser.containsKey("userName"));
        assertFalse(firstUser.containsKey("name"));
        assertFalse(firstUser.containsKey("emails"));
    }

    @Test
    public void findUsersWithSortBy() {
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.getForObject(usersEndpoint + "?sortBy=emails.value", Map.class);
        @SuppressWarnings("unchecked")
        Map<String, Object> results = response.getBody();
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue((Integer) results.get("totalResults") > 0, "There should be more than zero users");
    }

    @Test
    public void findUsersWithPagination() {
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning.getForObject(usersEndpoint + "?startIndex=2&count=3", Map.class);
        @SuppressWarnings("unchecked")
        Map<String, Object> results = response.getBody();
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertTrue((Integer) results.get("totalResults") > 0, "There should be more than zero users");
        assertEquals(2, results.get("startIndex"));
    }

    @BeforeEach
    public void setupScimUsers() {
        scimUsers = new ArrayList<>();
    }

    @AfterEach
    public void teardownScimUsers() {
        for (ScimUser scimUser : scimUsers) {
            deleteUser(scimUser.getId(), scimUser.getVersion());
        }
    }

    @Test
    public void findUsersWithExtremePagination() {
        for (int i = 0; i < 501; i++) {
            ResponseEntity<ScimUser> scimUserResponseEntity = createUser(
                    new RandomValueStringGenerator().generate().toLowerCase(),
                    new RandomValueStringGenerator().generate().toLowerCase(),
                    new RandomValueStringGenerator().generate().toLowerCase(),
                    new RandomValueStringGenerator().generate().toLowerCase()
            );
            scimUsers.add(scimUserResponseEntity.getBody());
        }

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> response = serverRunning
                .getForObject(usersEndpoint + "?startIndex=0&count=501", Map.class);
        @SuppressWarnings("unchecked")
        Map<String, Object> results = response.getBody();
        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertThat((Integer) results.get("totalResults"), greaterThan(500));
        assertThat(results.get("itemsPerPage"), is(500));
        assertThat(results.get("startIndex"), is(1));
    }
}
