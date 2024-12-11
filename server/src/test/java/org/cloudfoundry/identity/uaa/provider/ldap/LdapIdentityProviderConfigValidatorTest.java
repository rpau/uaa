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

package org.cloudfoundry.identity.uaa.provider.ldap;


import org.cloudfoundry.identity.uaa.provider.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

public class LdapIdentityProviderConfigValidatorTest {

    LdapIdentityProviderConfigValidator validator;

    @BeforeEach
    public void setup() {
        validator = spy(new LdapIdentityProviderConfigValidator());
    }

    @Test
    public void null_identity_provider() {
        Throwable exception = assertThrows(IllegalArgumentException.class, () ->
                validator.validate((IdentityProvider<AbstractIdentityProviderDefinition>) null));
        assertTrue(exception.getMessage().contains("Provider cannot be null"));
    }

    @Test
    public void invalid_ldap_origin() {
        Throwable exception = assertThrows(IllegalArgumentException.class, () -> {
            IdentityProvider<LdapIdentityProviderDefinition> ldap = new IdentityProvider<>();
            ldap.setType(LDAP);
            ldap.setOriginKey("other");
            validator.validate(ldap);
        });
        assertTrue(exception.getMessage().contains("LDAP provider originKey must be set to '%s'".formatted(LDAP)));
    }


    @Test
    public void valid_ldap_origin() {
        IdentityProvider<LdapIdentityProviderDefinition> ldap = new IdentityProvider<>();
        ldap.setType(LDAP);
        ldap.setOriginKey(LDAP);
        doNothing().when(validator).validate(any(AbstractIdentityProviderDefinition.class));
        validator.validate(ldap);
        verify(validator, times(1)).validate((AbstractIdentityProviderDefinition) isNull());

    }
}