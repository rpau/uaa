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
package org.cloudfoundry.identity.uaa.integration.feature;

import org.cloudfoundry.identity.uaa.ServerRunningExtension;
import org.cloudfoundry.identity.uaa.oauth.client.test.OAuth2ContextConfiguration;
import org.cloudfoundry.identity.uaa.util.LinkedMaskingMultiValueMap;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

@SpringJUnitConfig(classes = DefaultIntegrationTestConfig.class)
@OAuth2ContextConfiguration(OAuth2ContextConfiguration.ClientCredentials.class)
public class PasswordIT {

    @RegisterExtension
    private static final ServerRunningExtension serverRunning = ServerRunningExtension.connect();

    @Value("${integration.test.base_url}")
    String baseUrl;

    private RestTemplate getPostTemplate(MultiValueMap<String, String> headers) {
        RestTemplate restTemplate = new RestTemplate();
        headers.add("Content-Type", MediaType.APPLICATION_FORM_URLENCODED_VALUE);
        headers.add("Accept", MediaType.APPLICATION_JSON_VALUE);
        return restTemplate;
    }

    private RequestEntity getRequestEntity(MultiValueMap<String, String> headers, String s) {
        return new RequestEntity(headers, HttpMethod.POST, URI.create(baseUrl + s));
    }

    @Test
    public void getClientCredentials() {
        MultiValueMap<String, String> headers = new LinkedMaskingMultiValueMap<>();
        RestTemplate restTemplate = getPostTemplate(headers);
        RequestEntity requestEntity = getRequestEntity(headers,
                "/oauth/token?client_id=client_with_bcrypt_prefix&client_secret=password&grant_type=client_credentials");
        ResponseEntity<Void> responseEntity = restTemplate.exchange(requestEntity, Void.class);

        assertEquals(200, responseEntity.getStatusCodeValue(), "Status 200 expected");
    }

    @Test
    public void getClientCredentialsInvalid() {
        MultiValueMap<String, String> headers = new LinkedMaskingMultiValueMap<>();
        headers.add("Authorization", "Basic YWRtaW4lMDA6YWRtaW5zZWNyZXQ=");
        RestTemplate restTemplate = getPostTemplate(headers);
        RequestEntity requestEntity = getRequestEntity(headers,
                "/oauth/token?grant_type=client_credentials");
        try {
            restTemplate.exchange(requestEntity, Void.class);
        } catch (HttpClientErrorException ex) {
            assertEquals(401, ex.getStatusCode().value(), "Status 401 expected, but received: " + ex.getStatusCode().value()
                    + " with description " + ex.getResponseHeaders().get(HttpHeaders.WWW_AUTHENTICATE).get(0));
            return;
        }
        fail("not expected");
    }
}
