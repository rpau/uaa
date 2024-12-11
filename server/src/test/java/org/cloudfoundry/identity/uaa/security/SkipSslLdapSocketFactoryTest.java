package org.cloudfoundry.identity.uaa.security;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SkipSslLdapSocketFactoryTest {

    @Test
    void defaultInstanceIsSkipSslLdapSocketFactory() {
        Object ldapFactory = SkipSslLdapSocketFactory.getDefault();
        assertThat(ldapFactory).isNotNull();
        assertThat(ldapFactory instanceof SkipSslLdapSocketFactory).isTrue();
        assertThat(SkipSslLdapSocketFactory.getDefault() instanceof SkipSslLdapSocketFactory).isTrue();
    }
}
