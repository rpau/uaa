package org.cloudfoundry.identity.uaa.oauth.client;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ClientJwtCredentialTest {

    @Test
    void parse() {
        assertThatNoException().isThrownBy(() -> ClientJwtCredential.parse("[{\"iss\":\"http://localhost:8080/uaa\",\"sub\":\"client_with_jwks_trust\"}]"));
        List<ClientJwtCredential> federationList = ClientJwtCredential.parse("[{\"iss\":\"http://localhost:8080/uaa\",\"sub\":\"client_with_jwks_trust\"},{\"iss\":\"http://localhost:8080/uaa\"}]");
        assertThat(federationList).hasSize(2);
    }

    @Test
    void constructor() {
        ClientJwtCredential jwtCredential = new ClientJwtCredential("subject", "issuer", "audience");
        assertThat(jwtCredential)
                .returns("subject", ClientJwtCredential::getSubject)
                .returns("issuer", ClientJwtCredential::getIssuer)
                .returns("audience", ClientJwtCredential::getAudience)
                .returns(true, ClientJwtCredential::isValid);
        jwtCredential = new ClientJwtCredential();
        assertThat(jwtCredential.isValid()).isFalse();
    }

    @Test
    void testDeserializer() {
        assertThat(ClientJwtCredential.parse("[{\"iss\":\"issuer\"}]").iterator().next().isValid()).isFalse();
    }

    @Test
    void deserializerException() {
        assertThatThrownBy(() -> ClientJwtCredential.parse("[\"iss\":\"issuer\"]"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
