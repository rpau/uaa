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

package org.cloudfoundry.identity.uaa.web;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.View;

import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * @author Dave Syer
 */
public class ForwardAwareInternalResourceViewResolverTests {

    private final ForwardAwareInternalResourceViewResolver resolver = new ForwardAwareInternalResourceViewResolver();

    private final MockHttpServletRequest request = new MockHttpServletRequest();

    private final GenericApplicationContext context = new GenericApplicationContext();

    @BeforeEach
    public void start() {
        ServletRequestAttributes attributes = new ServletRequestAttributes(request);
        LocaleContextHolder.setLocale(request.getLocale());
        RequestContextHolder.setRequestAttributes(attributes);
        context.refresh();
    }

    @AfterEach
    public void clean() {
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    public void testResolveNonForward() throws Exception {
        resolver.setApplicationContext(context);
        View view = resolver.resolveViewName("foo", Locale.US);
        assertNotNull(view);
    }

    @Test
    public void testResolveRedirect() throws Exception {
        resolver.setApplicationContext(context);
        View view = resolver.resolveViewName("redirect:foo", Locale.US);
        assertNotNull(view);
    }

    @Test
    public void testResolveForwardWithAccept() throws Exception {
        request.addHeader("Accept", "application/json");
        resolver.setApplicationContext(context);
        View view = resolver.resolveViewName("forward:foo", Locale.US);
        assertNotNull(view);
    }

    @Test
    public void testResolveForwardWithUnparseableAccept() throws Exception {
        request.addHeader("Accept", "bar");
        resolver.setApplicationContext(context);
        View view = resolver.resolveViewName("forward:foo", Locale.US);
        assertNotNull(view);
    }

}
