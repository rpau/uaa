package org.cloudfoundry.identity.uaa.user;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.user.UaaUserMatcher.aUaaUser;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;

class UaaUserTests {
    @Nested
    class EmailFrom {
        @Nested
        class WhenInputDoesNotContainAtSymbol {
            @Test
            void constructsEmailFromInputAndDefaultDomain() {
                final String name = "user";
                assertThat(UaaUser.emailFrom(name)).isEqualTo(name + "@" + UaaUser.DEFAULT_EMAIL_DOMAIN);
            }
        }

        @Nested
        class WhenInputContainsLeadingAtSymbol {
            @Test
            void constructsEmailFromInputAndDefaultDomain() {
                final String name = "user";
                assertThat(UaaUser.emailFrom("@" + name)).isEqualTo(name + "@" + UaaUser.DEFAULT_EMAIL_DOMAIN);
            }
        }

        @Nested
        class WhenInputContainsTrailingAtSymbol {
            @Test
            void constructsEmailFromInputAndDefaultDomain() {
                final String name = "user";
                assertThat(UaaUser.emailFrom(name + "@")).isEqualTo(name + "@" + UaaUser.DEFAULT_EMAIL_DOMAIN);
            }
        }

        @Nested
        class WhenInputLooksLikeAnEmailAddress {
            @Test
            void returnsTheInput() {
                final String name = "user@example.com";
                assertThat(UaaUser.emailFrom(name)).isEqualTo(name);
            }
        }
    }

    @Nested
    class FromIncompletePrototype {
        @Nested
        class WhenMissingUsername {
            @Test
            void defaultsUsernameToEmail() {
                UaaUser user = UaaUser.createWithDefaults(u -> u.withEmail("user@example.com"));
                assertThat(user, aUaaUser().withUsername("user@example.com"));
            }

            @Test
            void defaultsUsernameToUnknownWhenNoEmailPresent() {
                UaaUser user = UaaUser.createWithDefaults(u -> {
                });
                assertThat(user, aUaaUser().withUsername(UaaUser.DEFAULT_USER_NAME));
            }
        }

        @Nested
        class WhenMissingEmail {
            @Test
            void defaultsEmailFromUsername() {
                UaaUser user = UaaUser.createWithDefaults(u -> u.withUsername("name"));
                assertThat(user, aUaaUser().withEmail("name" + "@" + UaaUser.DEFAULT_EMAIL_DOMAIN));
            }
        }

        @Nested
        class WhenMissingGivenName {
            @Test
            void defaultsGivenNameByExtractingTheUsernameFromAValidEmailAddress() {
                UaaUser user = UaaUser.createWithDefaults(u -> u.withUsername("user").withEmail("name@example.com"));
                assertThat(user, aUaaUser().withGivenName("name"));
            }

            @Test
            void defaultsGivenNameByExtractingTheUsernameFromAnInvalidEmailAddress() {
                UaaUser user = UaaUser.createWithDefaults(u -> u.withUsername("user").withEmail("invalid-email"));
                assertThat(user, aUaaUser().withGivenName("invalid-email"));
            }
        }

        @Nested
        class WhenMissingFamilyName {
            @Test
            void defaultsFamilyNameByExtractingTheUsernameFromTheEmailAddress() {
                UaaUser user = UaaUser.createWithDefaults(u -> u.withUsername("user").withEmail("name@example.com"));
                assertThat(user, aUaaUser().withFamilyName("example.com"));
            }

            @Test
            void defaultsGivenNameByExtractingTheUsernameFromTheEmailAddress() {
                UaaUserPrototype prototype =
                        new UaaUserPrototype()
                                .withUsername("user")
                                .withEmail("not-an-email");

                UaaUser user = UaaUser.createWithDefaults(u -> u.withUsername("user").withEmail("invalid-email"));
                assertThat(user, aUaaUser().withGivenName("invalid-email"));
            }
        }

        @Nested
        class WhenMissingCreated {
            @Test
            void defaultsToNow() {
                Date now = new Date();

                UaaUser user = UaaUser.createWithDefaults(u -> u.withUsername("user"));
                assertThat(user, aUaaUser().withCreated(greaterThanOrEqualTo(now)));
            }
        }

        @Nested
        class WhenMissingModified {
            @Test
            void defaultsToNow() {
                Date now = new Date();

                UaaUser user = UaaUser.createWithDefaults(u -> u.withUsername("user"));
                assertThat(user, aUaaUser().withModified(greaterThanOrEqualTo(user.getCreated())));
                assertThat(user, aUaaUser().withModified(greaterThanOrEqualTo(now)));
            }
        }
    }
}
