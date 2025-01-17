package org.cloudfoundry.identity.uaa.db;

import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.tomcat.jdbc.pool.DataSource;
import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.TestPropertySource;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@WithDatabaseContext
@TestPropertySource(properties = {
        "database.initialsize=0",
        "database.validationquerytimeout=5",
        "database.connecttimeout=5",
})
class DatabaseParametersTests {

    private Vendor vendor;

    @Autowired
    private DataSource dataSource;

    @BeforeEach
    void setUp(@Autowired DatabaseUrlModifier databaseUrlModifier) {
        vendor = databaseUrlModifier.getDatabaseType();
    }

    @Test
    void initial_size() {
        assertThat(dataSource.getInitialSize()).isZero();
    }

    @Test
    void validation_query_timeout() {
        assertThat(dataSource.getValidationQueryTimeout()).isEqualTo(5);
    }

    @Test
    void connection_timeout_property_set() {
        switch (vendor) {
            case mysql: {
                assertThat(getUrlParameter("connectTimeout")).isEqualTo("5000");
                break;
            }
            case postgresql: {
                assertThat(getUrlParameter("connectTimeout")).isEqualTo("5");
                break;
            }
            case hsqldb: {
                break;
            }
            default:
                throw new IllegalStateException("Unrecognized database: " + vendor);
        }
    }

    String getUrlParameter(String name) {
        String dburl = dataSource.getUrl();
        URI uri = URI.create("http://localhost" + dburl.substring(dburl.indexOf("?")));
        List<NameValuePair> pairs = URLEncodedUtils.parse(uri, StandardCharsets.UTF_8);
        for (NameValuePair p : pairs) {
            if (name.equals(p.getName())) {
                return p.getValue();
            }
        }
        return null;
    }
}
