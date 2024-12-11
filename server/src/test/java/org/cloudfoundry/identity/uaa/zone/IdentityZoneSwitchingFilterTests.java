/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static org.mockito.Mockito.mock;

public class IdentityZoneSwitchingFilterTests {

    @Test
    public void testStripPrefix() {
        String zoneId = new RandomValueStringGenerator().generate();
        IdentityZoneSwitchingFilter filter = new IdentityZoneSwitchingFilter(mock(IdentityZoneProvisioning.class));
        Assertions.assertEquals("zones." + zoneId + ".admin", filter.stripPrefix("zones." + zoneId + ".admin", zoneId));
        Assertions.assertEquals("zones." + zoneId + ".read", filter.stripPrefix("zones." + zoneId + ".read", zoneId));
        Assertions.assertEquals("clients.admin", filter.stripPrefix("zones." + zoneId + ".clients.admin", zoneId));
        Assertions.assertEquals("clients.read", filter.stripPrefix("zones." + zoneId + ".clients.read", zoneId));
        Assertions.assertEquals("idps.read", filter.stripPrefix("zones." + zoneId + ".idps.read", zoneId));
    }

}