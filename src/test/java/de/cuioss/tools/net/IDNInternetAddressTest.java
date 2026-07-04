/*
 * Copyright © 2025 CUI-OpenSource-Software (info@cuioss.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.tools.net;

import org.junit.jupiter.api.Test;

import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IDNInternetAddressTest {

    @Test
    void specialCharacters() {
        assertEquals("MD KARIN KALLWITZ <user1@xn--mller-kva.com>",
                IDNInternetAddress.encode("MD KARIN KALLWITZ <user1@müller.com>"));
        assertEquals("user1@xn--mller-kva.com", IDNInternetAddress.encode("user1@müller.com"));
        assertEquals("user1@xn--msser-kva.com", IDNInternetAddress.encode("user1@müßer.com"));
    }

    @Test
    void noSpecialCharacters() {
        assertEquals("MD KARIN KALLWITZ <user1@mueller.com>",
                IDNInternetAddress.encode("MD KARIN KALLWITZ <user1@mueller.com>"));
        assertEquals("user1@mueller.com", IDNInternetAddress.encode("user1@mueller.com"));
    }

    @Test
    void roundTripComplete() {
        var orig = "MD KARIN KALLWITZ <user1@müller.com>";
        assertEquals("MD KARIN KALLWITZ <user1@xn--mller-kva.com>", IDNInternetAddress.encode(orig));
        assertEquals(orig, IDNInternetAddress.decode(IDNInternetAddress.encode(orig)));

        orig = "user1@müller.com";
        assertEquals("user1@xn--mller-kva.com", IDNInternetAddress.encode(orig));
        assertEquals(orig, IDNInternetAddress.decode(IDNInternetAddress.encode(orig)));
    }

    @Test
    void shouldHandleDomainsLongerThan64Characters() {
        // RFC 5321 permits domains of up to 255 characters, each label up to 63
        final var longLabel = "a".repeat(50);
        final var domain = "müller." + longLabel + ".example.com";
        assertTrue(domain.length() > 64);

        var orig = "user1@" + domain;
        var encoded = IDNInternetAddress.encode(orig);
        assertEquals("user1@xn--mller-kva." + longLabel + ".example.com", encoded);
        assertEquals(orig, IDNInternetAddress.decode(encoded));

        orig = "MD KARIN KALLWITZ <user1@" + domain + ">";
        encoded = IDNInternetAddress.encode(orig);
        assertEquals("MD KARIN KALLWITZ <user1@xn--mller-kva." + longLabel + ".example.com>", encoded);
        assertEquals(orig, IDNInternetAddress.decode(encoded));
    }

    @Test
    void shouldHandleDisplayNamesLongerThan64Characters() {
        final var displayName = "M".repeat(70);
        final var orig = displayName + " <user1@müller.com>";
        final var encoded = IDNInternetAddress.encode(orig);
        assertEquals(displayName + " <user1@xn--mller-kva.com>", encoded);
        assertEquals(orig, IDNInternetAddress.decode(encoded));
    }

    @Test
    void shouldApplySanitizerOnEncode() {
        assertEquals("USER1@XN--MLLER-KVA.COM",
                IDNInternetAddress.encode("user1@müller.com", value -> value.toUpperCase(Locale.ROOT)));
        assertEquals("MD KARIN KALLWITZ <USER1@XN--MLLER-KVA.COM>",
                IDNInternetAddress.encode("md karin kallwitz <user1@müller.com>",
                        value -> value.toUpperCase(Locale.ROOT)));
    }

    @Test
    void shouldApplySanitizerOnDecode() {
        assertEquals("USER1@MÜLLER.COM",
                IDNInternetAddress.decode("user1@xn--mller-kva.com", value -> value.toUpperCase(Locale.ROOT)));
        assertEquals("MD KARIN KALLWITZ <USER1@MÜLLER.COM>",
                IDNInternetAddress.decode("md karin kallwitz <user1@xn--mller-kva.com>",
                        value -> value.toUpperCase(Locale.ROOT)));
    }

    @Test
    void shouldFallBackToUnconvertedDomainForMalformedIdn() {
        // 'domain..com' matches the address patterns but IDN.toASCII rejects the
        // empty label with an IllegalArgumentException; encode must fall back to
        // the unconverted domain instead of propagating the exception
        assertEquals("user1@domain..com", IDNInternetAddress.encode("user1@domain..com"));
        assertEquals("MD KARIN KALLWITZ <user1@domain..com>",
                IDNInternetAddress.encode("MD KARIN KALLWITZ <user1@domain..com>"));
    }

    @Test
    void shouldReturnNonMatchingInputSanitizedButUnmodified() {
        // Neither pattern matches input without an '@' character
        assertEquals("no-mail-address", IDNInternetAddress.encode("no-mail-address"));
        assertEquals("no-mail-address", IDNInternetAddress.decode("no-mail-address"));
        assertEquals("NO-MAIL-ADDRESS",
                IDNInternetAddress.encode("no-mail-address", value -> value.toUpperCase(Locale.ROOT)));
        assertEquals("NO-MAIL-ADDRESS",
                IDNInternetAddress.decode("no-mail-address", value -> value.toUpperCase(Locale.ROOT)));
    }

}
