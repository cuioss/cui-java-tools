/*
 * Copyright 2023 the original author or authors.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * https://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.tools.net;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class IDNInternetAddressTest {

    @Test
    void testSpecialCharacters() {
        assertEquals("MD KARIN KALLWITZ <user1@xn--mller-kva.com>",
                IDNInternetAddress.encode("MD KARIN KALLWITZ <user1@müller.com>"));
        assertEquals("user1@xn--mller-kva.com", IDNInternetAddress.encode("user1@müller.com"));
        assertEquals("user1@xn--msser-kva.com", IDNInternetAddress.encode("user1@müßer.com"));
    }

    @Test
    void testNoSpecialCharacters() {
        assertEquals("MD KARIN KALLWITZ <user1@mueller.com>",
                IDNInternetAddress.encode("MD KARIN KALLWITZ <user1@mueller.com>"));
        assertEquals("user1@mueller.com", IDNInternetAddress.encode("user1@mueller.com"));
    }

    @Test
    void testRoundTripComplete() {
        var orig = "MD KARIN KALLWITZ <user1@müller.com>";
        assertEquals("MD KARIN KALLWITZ <user1@xn--mller-kva.com>", IDNInternetAddress.encode(orig));
        assertEquals(orig, IDNInternetAddress.decode(IDNInternetAddress.encode(orig)));

        orig = "user1@müller.com";
        assertEquals("user1@xn--mller-kva.com", IDNInternetAddress.encode(orig));
        assertEquals(orig, IDNInternetAddress.decode(IDNInternetAddress.encode(orig)));
    }

}
