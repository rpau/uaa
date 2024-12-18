# Testing considerations

This document contains information about how the tests are structured and why.

## Types of test

There are two types of tests:

- Unit tests, which run tests on classes or subsets of the application in a single JVM. Those run with `./gradlew test`.
- Integration tests, which launch the UAA application and run web-based tests the running app. Those can be run with
  `./gradlew integrationTest`

## Helper scripts

There are helper scripts, `run-unit-tests.sh` and `run-integration-tests.sh`, which run the tests inside a docker
container. The docker container they run in contains the database against which to run the tests, as well as an LDAP
server. It is self-contained but lacks flexibility. It relies on custom-baked image that may not support arm64, and
can't work with your IDE.

However, since the scripts run a container with all dependencies, you do not need infrastructure to run against a
specified DB:

    $ run-unit-tests.sh <dbtype>

## Test databases

By default, the tests run against an in-memory DB, `hsqldb`. This DB is also present in the prod artifact, so that
UAA can also be ran standalone to test tweaks in a live instance.

To run these databases locally, use the docker-compose script:

    $ docker compose --file scripts/docker-compose.yaml up

If you wish to launch only one of the DBs, select the appropriate service name:

    $ docker compose --file scripts/docker-compose.yaml up postgresql

To run tests against either Postgres or MySQL, use the `postgresql` or `mysql` profile, to select the DB. Be sure
to add the `default` profile which will trigger seeding the database with some admin users, clients, etc. For example:

    $ ./gradlew '-Dspring.profiles.active=mysql,default test

To run tests from your IDE against a given database, you can (temporarily) annotate the test class:

```java

@ActiveProfiles({"mysql", "default"})
class MyCustomTests {
    @Test
    void foo() {
        // ...
    }
}
```

## Database-specific tests

Some tests only work on a single type of database, for example `MySqlDbMigrationIntegrationTest`; or do not work on a
given database, for example `JdbcClientMetadataProvisioningTest.createdByPadsTo36Chars`. You can turn tests on and off
based on the profile with custom annotations, `@DisabledIfProfile` and `@EnabledIfProfile`, for example:

```java
// Only run on either mysql or postgresql
@EnabledIfProfile({"mysql", "postgresql"})
class RealDbOnlyTests {

}

// or:

class SomeTests {

    // Do not run when there is either mysql or postgresql
    @DisabledIfProfile({"mysql", "postgres"})
    void notOnRealDb() {

    }

}
```

## Test pollution

There might be test pollution when tests are run in parallel, or even between projects. For example, when you run

    $ ./gradlew test

It will run tests in both `cloudfoundry-identity-server` and `cloudfoundry-identity-uaa` projects. Both need a database,
and both do sometimes clean up the database.

To avoid test pollution, 24 databases are created, and each Gradle "worker" thread gets its own database. A Gradle
worker has a numeric `id`, and each time a new task is spun up, the idea of the worker picking up the task increases.
So there are 24 DBs with names `uaa_1`, `uaa_2`, ... created, and usually the worker ID stays below 24 and there are
enough databases for each test.

However, if the gradle daemon is kept running in the background and is re-used for subsequent tasks, e.g. by doing:

    $ ./gradlew test # first run
    # do some code changes
    $ ./gradlew test

You will get new workers with IDs > 24. It is recommended you run your Gradle in no-daemon mode when running tests:

    $ ./gradlew test --no-daemon

It will be slightly slower to start up (a few seconds), but the tests take multiple minutes and so the gain of using
a daemon is not worth the trouble.

## Timezone issues

The UAA and its DB server _MUST_ have the same timezone, because dates are not uniformly stored in UTC and timezones
do matter. Specifically for MySQL, there are issues when your local host is ahead of UTC, because:

1. The default containers runs in UTC
2. When calling `current_timestamp` the value is in UTC
3. But when calling a prepared statement from JDBC with a Date/Timestamp/time-based the timezone is sent to the server

So, when running e.g. in `Europe/Paris` (CET):

```java
jdbcTemplate.queryForObject("SELECT CURRENT_TIMESTAMP",String .class);
// will return 15:00UTC
// if the TZ is dropped, it is recorded as 15:00
jdbcTemplate.update("UPDATE foo SET updated=?",new Date(System.currentTimeMillis()));
// will insert 16:00CET
// if the TZ is dropped this is recorded as 16:00
```

For this reason, we update the MySQL container in `docker-compose.yml` to have the same timezone as the host through
the `$TZ` env var.

If you have timing-based issues in your test, ensure that you set `$TZ` before starting docker compose, e.g.:

    $ TZ="Europe/Paris" docker compose up

It is not required, and MySQL will default to using UTC.