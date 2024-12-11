package org.cloudfoundry.identity.uaa.zone;

import org.junit.jupiter.api.Test;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertThrows;


class UserConfigValidatorTest {

    @Test
    void testDefaultConfig() throws InvalidIdentityZoneConfigurationException {
        UserConfigValidator.validate(new UserConfig()); // defaultGroups not empty, allowedGroups is null
    }

    @Test
    void testNullConfig() throws InvalidIdentityZoneConfigurationException {
        UserConfigValidator.validate(null);
    }

    @Test
    void testAllowedGroupsEmpty() throws InvalidIdentityZoneConfigurationException {
        UserConfig userConfig = new UserConfig();
        userConfig.setAllowedGroups(Collections.emptyList());
        UserConfigValidator.validate(userConfig);
    }

    @Test
    void testNoGroupsAllowed() {
        assertThrows(InvalidIdentityZoneConfigurationException.class, () -> {
            UserConfig userConfig = new UserConfig();
            userConfig.setDefaultGroups(Collections.emptyList());
            userConfig.setAllowedGroups(Collections.emptyList()); // no groups allowed
            UserConfigValidator.validate(userConfig);
        });
    }

    @Test
    void testNoUsersAllowed() {
        assertThrows(InvalidIdentityZoneConfigurationException.class, () -> {
            UserConfig userConfig = new UserConfig();
            userConfig.setMaxUsers(0);
            UserConfigValidator.validate(userConfig);
        });
    }
}