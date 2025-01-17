/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */
package org.cloudfoundry.identity.uaa.provider;

import java.util.List;

public interface IdentityProviderProvisioning {

    IdentityProvider create(IdentityProvider identityProvider, String zoneId);

    IdentityProvider update(IdentityProvider identityProvider, String zoneId);

    boolean idpWithAliasExistsInZone(String zoneId);

    IdentityProvider retrieve(String id, String zoneId);

    List<IdentityProvider> retrieveActive(String zoneId);

    List<IdentityProvider> retrieveActiveByTypes(String zoneId, String... types);

    List<IdentityProvider> retrieveAll(boolean activeOnly, String zoneId);

    IdentityProvider retrieveByOrigin(String origin, String zoneId);

    IdentityProvider retrieveByExternId(String externId, String type, String zoneId);

    default IdentityProvider retrieveByOriginIgnoreActiveFlag(String origin, String zoneId) {
        return retrieveByOrigin(origin, zoneId);
    }
}
