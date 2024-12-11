package org.cloudfoundry.identity.uaa.test;

import org.cloudfoundry.identity.uaa.oauth.client.test.TestAccounts;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.cloudfoundry.identity.uaa.test.UaaTestAccounts.UAA_TEST_PASSWORD;
import static org.cloudfoundry.identity.uaa.test.UaaTestAccounts.UAA_TEST_USERNAME;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class UaaTestAccountsTest {

    private TestAccounts testAccounts;
    private String originalUaaTestUsername;
    private String originalUaaTestPassword;

    @BeforeEach
    public void setUp() {
        testAccounts = UaaTestAccounts.standard(null);
        originalUaaTestUsername = System.getProperty(UAA_TEST_USERNAME);
        originalUaaTestPassword = System.getProperty(UAA_TEST_PASSWORD);
    }

    @AfterEach
    public void restoreProperties() {
        if (originalUaaTestUsername == null) {
            System.clearProperty(UAA_TEST_USERNAME);
        } else {
            System.setProperty(UAA_TEST_USERNAME, originalUaaTestUsername);
        }
        if (originalUaaTestPassword == null) {
            System.clearProperty(UAA_TEST_PASSWORD);
        } else {
            System.setProperty(UAA_TEST_PASSWORD, originalUaaTestPassword);
        }
    }

    @Test
    public void testGetDefaultUsername() {
        assertEquals(UaaTestAccounts.DEFAULT_USERNAME, testAccounts.getUserName());
    }

    @Test
    public void testGetAlternateUsername() {
        String username = "marissa2";
        System.setProperty(UAA_TEST_USERNAME, username);
        assertEquals(username, testAccounts.getUserName());
    }

    @Test
    public void testGetDefaultPassword() {
        assertEquals(UaaTestAccounts.DEFAULT_PASSWORD, testAccounts.getPassword());
    }

    @Test
    public void testGetAlternatePassword() {
        String password = "koala2";
        System.setProperty(UAA_TEST_PASSWORD, password);
        assertEquals(password, testAccounts.getPassword());
    }
}
