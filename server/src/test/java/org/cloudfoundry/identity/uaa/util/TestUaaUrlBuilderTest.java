package org.cloudfoundry.identity.uaa.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.assertThrows;

class TestUaaUrlBuilderTest {
    private TestUaaUrlBuilder builder;

    @BeforeEach
    public void setup() {
        builder = new TestUaaUrlBuilder();
        ReflectionTestUtils.setField(builder, "systemDomain", "foo.cf.com");
    }

    @Test
    void informativeError_whenNoSystemDomain() {
        ReflectionTestUtils.setField(builder, "systemDomain", "");
        assertThrows(RuntimeException.class, () -> builder.build());
    }

    @Test
    void build_returnsUaaUrl() {
        String url = builder.build();
        Assertions.assertEquals("https://uaa.foo.cf.com/", url);
    }

    @Test
    void setScheme_canChangeScheme() {
        String url = builder.withScheme("http").build();
        Assertions.assertEquals("http://uaa.foo.cf.com/", url);
    }

    @Test
    void setPath_canAddPathStuff() {
        String url = builder.withPath("/oauth/authorize").build();
        Assertions.assertEquals("https://uaa.foo.cf.com/oauth/authorize", url);
    }

    @Test
    void setSubdomain_canAddSubdomain() {
        String url = builder.withSubdomain("my-zone").build();
        Assertions.assertEquals("https://my-zone.uaa.foo.cf.com/", url);
    }

    @Test
    void stringingItAllTogether() {
        String url = builder.withScheme("http")
                .withPath("/oauth/authorize")
                .withSubdomain("my-zone").build();
        Assertions.assertEquals("http://my-zone.uaa.foo.cf.com/oauth/authorize", url);
    }

    @Test
    void handlesExtraSlashesProperly() {
        ReflectionTestUtils.setField(builder, "systemDomain", "foo.cf.com/");
        String url = builder.withPath("/oauth/authorize").build();
        Assertions.assertEquals("https://uaa.foo.cf.com/oauth/authorize", url);

        ReflectionTestUtils.setField(builder, "systemDomain", "foo.cf.com/");
        String url2 = builder.withPath("oauth/authorize").build();
        Assertions.assertEquals("https://uaa.foo.cf.com/oauth/authorize", url2);

        ReflectionTestUtils.setField(builder, "systemDomain", "foo.cf.com");
        String url3 = builder.withPath("oauth/authorize").build();
        Assertions.assertEquals("https://uaa.foo.cf.com/oauth/authorize", url3);
    }
}
