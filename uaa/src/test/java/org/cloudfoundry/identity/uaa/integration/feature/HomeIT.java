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

import org.cloudfoundry.identity.uaa.oauth.client.test.TestAccounts;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

import static org.assertj.core.api.Assertions.assertThat;

@SpringJUnitConfig(classes = DefaultIntegrationTestConfig.class)
class HomeIT {
    @Autowired
    TestAccounts testAccounts;

    @Autowired
    @RegisterExtension
    private IntegrationTestExtension integrationTestExtension;

    @Autowired
    WebDriver webDriver;

    @Value("${integration.test.base_url}")
    String baseUrl;

    private HomePagePerspective asOnHomePage;

    @AfterEach
    void logout_and_clear_cookies() {
        try {
            webDriver.get(baseUrl + "/logout.do");
        } catch (org.openqa.selenium.TimeoutException x) {
            //try again - this should not be happening - 20 second timeouts
            webDriver.get(baseUrl + "/logout.do");
        }
        webDriver.manage().deleteAllCookies();
    }

    @BeforeEach
    void setUp() {
        logout_and_clear_cookies();
        webDriver.get(baseUrl + "/login");
        webDriver.findElement(By.name("username")).sendKeys(testAccounts.getUserName());
        webDriver.findElement(By.name("password")).sendKeys(testAccounts.getPassword());
        webDriver.findElement(By.xpath("//input[@value='Sign in']")).click();

        asOnHomePage = new HomePagePerspective(webDriver, testAccounts.getUserName());
    }

    @Test
    void message() {
        assertThat(webDriver.findElement(By.tagName("h1")).getText()).isEqualTo("Where to?");
    }

    @Test
    void theHeaderDropdown() {
        assertThat(asOnHomePage.getUsernameElement()).isNotNull();
        assertThat(asOnHomePage.getAccountSettingsElement().isDisplayed()).isFalse();
        assertThat(asOnHomePage.getSignOutElement().isDisplayed()).isFalse();

        asOnHomePage.getUsernameElement().click();

        assertThat(asOnHomePage.getAccountSettingsElement().isDisplayed()).isTrue();
        assertThat(asOnHomePage.getSignOutElement().isDisplayed()).isTrue();

        asOnHomePage.getAccountSettingsElement().click();

        assertThat(webDriver.findElement(By.cssSelector("h1")).getText()).contains("Account Settings");
    }

    static class HomePagePerspective {
        private final WebDriver webDriver;
        private final String username;

        public HomePagePerspective(WebDriver webDriver, String username) {
            this.webDriver = webDriver;
            this.username = username;
        }

        public WebElement getUsernameElement() {
            return getWebElementWithText(username);
        }

        public WebElement getAccountSettingsElement() {
            return getWebElementWithText("Account Settings");
        }

        public WebElement getSignOutElement() {
            return getWebElementWithText("Sign Out");
        }

        private WebElement getWebElementWithText(String text) {
            return webDriver.findElement(By.xpath("//*[text()='" + text + "']"));
        }
    }
}
