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

package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.authentication.manager.UsernamePasswordExtractingAuthenticationManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.junit.jupiter.api.Assertions.assertSame;

/**
 * @author Dave Syer
 */
public class UsernamePasswordExtractingAuthenticationManagerTests {

    private final AuthenticationManager delegate = Mockito.mock(AuthenticationManager.class);

    private final UsernamePasswordExtractingAuthenticationManager manager = new UsernamePasswordExtractingAuthenticationManager(
            delegate);

    @BeforeEach
    public void setUp() {
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    public void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void testAuthenticate() {
        Authentication expected = new TestingAuthenticationToken("bar", "foo",
                AuthorityUtils.commaSeparatedStringToAuthorityList("USER"));
        Mockito.when(delegate.authenticate(ArgumentMatchers.any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(expected);
        Authentication output = manager.authenticate(new TestingAuthenticationToken("foo", "bar"));
        assertSame(expected, output);
    }

    @Test
    public void testUsernamePassword() {
        Authentication expected = new UsernamePasswordAuthenticationToken("bar", "foo",
                AuthorityUtils.commaSeparatedStringToAuthorityList("USER"));
        Mockito.when(delegate.authenticate(ArgumentMatchers.any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(expected);
        Authentication output = manager.authenticate(expected);
        assertSame(expected, output);
    }

}
