package org.cloudfoundry.identity.uaa.oauth.provider.code;

import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class InMemoryAuthorizationCodeServicesTest {

    private InMemoryAuthorizationCodeServices inMemoryAuthorizationCodeServices;
    private OAuth2Authentication oAuth2Authentication;


    @BeforeEach
    void setUp() throws Exception {
        inMemoryAuthorizationCodeServices = new InMemoryAuthorizationCodeServices();
        oAuth2Authentication = mock(OAuth2Authentication.class);
    }

    @Test
    void store() {
        inMemoryAuthorizationCodeServices.store("code", oAuth2Authentication);
        assertThat(inMemoryAuthorizationCodeServices.authorizationCodeStore.get("code")).isEqualTo(oAuth2Authentication);
    }

    @Test
    void remove() {
        assertThat(inMemoryAuthorizationCodeServices.authorizationCodeStore.size()).isEqualTo(0);
        inMemoryAuthorizationCodeServices.store("code", oAuth2Authentication);
        assertThat(inMemoryAuthorizationCodeServices.authorizationCodeStore.size()).isEqualTo(1);
        inMemoryAuthorizationCodeServices.remove("code");
        assertThat(inMemoryAuthorizationCodeServices.authorizationCodeStore.size()).isEqualTo(0);
    }
}