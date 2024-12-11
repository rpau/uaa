/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.web;

import org.cloudfoundry.identity.uaa.util.EmptyEnumerationOfString;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class HttpHeadersFilterRequestWrapperTest {

    public static List<String> BAD_HEADERS = Arrays.asList("X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Prefix", "Forwarded");

    MockHttpServletRequest mock;
    private HttpHeadersFilterRequestWrapper request;

    @BeforeEach
    public void setUp() {
        mock = new MockHttpServletRequest(HttpMethod.GET.name(), "http://localhost:8080/uaa/login");
        mock.addHeader("X-Forwarded-For", "proxy-ip");
        mock.addHeader("X-Forwarded-Host", "proxy-host");
        mock.addHeader("X-Forwarded-Proto", "proxy-host");
        mock.addHeader("X-Forwarded-Prefix", "/otherpath");
        mock.addHeader("Forwarded", "for=proxy-ip;host=proxy-host;for=my-proxy;by=somebody-else");
        mock.addHeader("Other-header", "other-value");
        request = new HttpHeadersFilterRequestWrapper(BAD_HEADERS, mock);
    }

    @AfterEach
    public void tearDown() {
    }

    @Test
    public void filter_is_case_insensitive() {
        request = new HttpHeadersFilterRequestWrapper(Collections.singletonList("x-forwarded-host"), mock);
        assertNull(request.getHeader("X-Forwarded-Host"));
        assertNotNull(request.getHeader("X-Forwarded-For"));
    }

    @Test
    public void null_filter_list() {
        request = new HttpHeadersFilterRequestWrapper(null, mock);
        List<String> actual = Collections.list(request.getHeaderNames());
        List<String> wanted = new ArrayList<>(BAD_HEADERS);
        wanted.add("Other-header");
        assertThat(actual, containsInAnyOrder(wanted.toArray()));
    }

    @Test
    public void filtered_available_headers() {
        request = new HttpHeadersFilterRequestWrapper(BAD_HEADERS, mock);
        List<String> actual = Collections.list(request.getHeaderNames());
        List<String> wanted = Collections.singletonList("Other-header");
        assertThat(actual, containsInAnyOrder(wanted.toArray()));
    }

    @Test
    public void non_filtered_available_headers() {
        request = new HttpHeadersFilterRequestWrapper(Collections.emptyList(), mock);
        List<String> actual = Collections.list(request.getHeaderNames());
        List<String> wanted = new ArrayList<>(BAD_HEADERS);
        wanted.add("Other-header");
        assertThat(actual, containsInAnyOrder(wanted.toArray()));
    }

    @Test
    public void filtered_x_forwarded_headers_single_header() {
        for (String header : BAD_HEADERS) {
            assertNull(request.getHeader(header), "Header %s should be filtered.".formatted(header));
        }
    }

    @Test
    public void non_filtered_x_forwarded_headers_single_header() {
        request = new HttpHeadersFilterRequestWrapper(Collections.emptyList(), mock);
        for (String header : BAD_HEADERS) {
            assertNotNull(request.getHeader(header), "Header %s should be present.".formatted(header));
        }
    }

    @Test
    public void filtered_x_forwarded_headers_multi_header() {
        for (String header : BAD_HEADERS) {
            assertFalse(request.getHeaders(header).hasMoreElements(), "Header %s should return empty enumeration.".formatted(header));
            assertSame(
                    EmptyEnumerationOfString.EMPTY_ENUMERATION,
                    request.getHeaders(header),
                    "Header %s should return singleton enumeration .".formatted(header)
            );
        }
    }

    @Test
    public void non_filtered_x_forwarded_headers_multi_header() {
        request = new HttpHeadersFilterRequestWrapper(Collections.emptyList(), mock);
        for (String header : BAD_HEADERS) {
            assertTrue(request.getHeaders(header).hasMoreElements(), "Header %s should return empty enumeration.".formatted(header));
            assertNotNull(
                    request.getHeaders(header).nextElement(),
                    "Header %s should return a value.".formatted(header)
            );
        }
    }

    @Test
    public void filter_creates_wrapper() {

    }

}