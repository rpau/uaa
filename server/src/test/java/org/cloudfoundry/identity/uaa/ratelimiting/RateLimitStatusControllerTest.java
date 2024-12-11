package org.cloudfoundry.identity.uaa.ratelimiting;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class RateLimitStatusControllerTest {

    RateLimitStatusController rateLimitStatusController = new RateLimitStatusController();

    @Test
    void rateLimitStatus() {
        String responseEntity = rateLimitStatusController.rateLimitStatus();
        assertNotNull(responseEntity);
        assertThat(responseEntity, containsString("\"status\" : \"DISABLED\""));
    }
}
