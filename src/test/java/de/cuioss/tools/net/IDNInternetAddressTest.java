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
        assertEquals("MD KARIN KALLWITZ <user1@xn--mller-kva.com>",
                IDNInternetAddress.encode(orig));
        assertEquals(orig, IDNInternetAddress.decode(IDNInternetAddress.encode(orig)));

        orig = "user1@müller.com";
        assertEquals("user1@xn--mller-kva.com", IDNInternetAddress.encode(orig));
        assertEquals(orig, IDNInternetAddress.decode(IDNInternetAddress.encode(orig)));
    }

}
