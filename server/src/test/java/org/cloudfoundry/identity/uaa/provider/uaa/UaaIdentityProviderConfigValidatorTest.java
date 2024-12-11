package org.cloudfoundry.identity.uaa.provider.uaa;

import org.cloudfoundry.identity.uaa.provider.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.LockoutPolicy;
import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;

class UaaIdentityProviderConfigValidatorTest {

    UaaIdentityProviderDefinition uaaIdentityProviderDef;
    UaaIdentityProviderConfigValidator configValidator;

    @BeforeEach
    public void setUp() {
        uaaIdentityProviderDef = new UaaIdentityProviderDefinition();
        uaaIdentityProviderDef.setPasswordPolicy(new PasswordPolicy(8, 8, 1, 1, 8, 1, 3));
        uaaIdentityProviderDef.setLockoutPolicy(new LockoutPolicy(1, 1, 1));
        configValidator = new UaaIdentityProviderConfigValidator();
    }

    @Test
    void nullConfigIsAllowed() {
        configValidator.validate((AbstractIdentityProviderDefinition) null);
    }

    @Test
    void nullLockoutPolicy_isAllowed() {
        uaaIdentityProviderDef.setLockoutPolicy(null);
        configValidator.validate(uaaIdentityProviderDef);
    }

    @Test
    void nullPasswordPolicy_isAllowed() {
        uaaIdentityProviderDef.setPasswordPolicy(null);
        configValidator.validate(uaaIdentityProviderDef);
    }

    @Test
    public void passwordPolicyIsNotNullAndIncomplete() {
        uaaIdentityProviderDef.setPasswordPolicy(new PasswordPolicy(8, 8, -1, 1, 8, 1, 3));
        assertThrows(IllegalArgumentException.class, () -> {
            configValidator.validate(uaaIdentityProviderDef);
        });
    }

    @Test
    public void lockoutPolicyIsNotNullAndIncomplete() {
        uaaIdentityProviderDef.setLockoutPolicy(new LockoutPolicy(-1, 1, 1));
        assertThrows(IllegalArgumentException.class, () -> {
            configValidator.validate(uaaIdentityProviderDef);
        });
    }

}
