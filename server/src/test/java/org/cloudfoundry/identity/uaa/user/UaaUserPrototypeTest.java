package org.cloudfoundry.identity.uaa.user;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class UaaUserPrototypeTest {

    @Test
    public void testGetPassword() {
        UaaUserPrototype prototype = new UaaUserPrototype()
                .withPassword("pass");
        assertEquals("pass", prototype.getPassword());
    }

    @Test
    public void testGetUserWithId() {
        UaaUserPrototype prototype = new UaaUserPrototype()
                .withUsername("name")
                .withEmail("email")
                .withPassword("pass");
        UaaUser userWithId = new UaaUser(prototype).id("new-id");
        assertEquals("new-id", userWithId.getId());
    }
}