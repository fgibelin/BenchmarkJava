/**
 * OWASP Benchmark Project
 *
 * <p>This file is part of the Open Web Application Security Project (OWASP) Benchmark Project.
 *
 * <p>The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, version 2.
 *
 * <p>The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU General Public License for more details.
 */
package org.owasp.benchmark.helpers;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class LDAPManagerTest {

    @Test
    void personUidFilterPreservesOrdinaryUid() {
        assertEquals(
                "(&(objectclass=person)(uid=alice))",
                LDAPManager.createPersonUidFilter("alice"));
    }

    @Test
    void personUidFilterEscapesFilterMetacharactersInUid() {
        assertEquals(
                "(&(objectclass=person)(uid=\\2a\\29\\28uid=\\2a\\29))",
                LDAPManager.createPersonUidFilter("*)(uid=*)"));
    }
}
