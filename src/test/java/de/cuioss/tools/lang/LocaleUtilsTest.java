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
package de.cuioss.tools.lang;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.Arrays;
import java.util.Locale;

import org.junit.jupiter.api.Test;

import de.cuioss.tools.string.MoreStrings;

/**
 * Unit tests for {@link LocaleUtils}.
 * <p>
 * COPIED FROM:
 * <a href="https://github.com/apache/commons-lang/blob/LANG_3_8_1/src/test/java/org/apache/commons/lang3/LocaleUtilsTest.java">...</a>
 */
@SuppressWarnings("deprecation") // Using deprecated constructor for backwards compatibility
class LocaleUtilsTest {

    /**
     * Pass in a valid language, test toLocale.
     *
     * @param language the language string
     */
    private static void assertValidToLocale(final String language) {
        final var locale = LocaleUtils.toLocale(language);
        assertNotNull(locale, "valid locale");
        assertEquals(language, locale.getLanguage());
        // country and variant are empty
        assertTrue(locale.getCountry().isEmpty());
        assertTrue(locale.getVariant().isEmpty());
    }

    /**
     * Pass in a valid language, test toLocale.
     *
     * @param localeString to pass to toLocale()
     * @param language     of the resulting Locale
     * @param country      of the resulting Locale
     */
    private static void assertValidToLocale(final String localeString, final String language, final String country) {
        final var locale = LocaleUtils.toLocale(localeString);
        assertNotNull(locale, "valid locale");
        assertEquals(language, locale.getLanguage());
        assertEquals(country, locale.getCountry());
        // variant is empty
        assertTrue(locale.getVariant().isEmpty());
    }

    /**
     * Pass in a valid language, test toLocale.
     *
     * @param localeString to pass to toLocale()
     * @param language     of the resulting Locale
     * @param country      of the resulting Locale
     * @param variant      of the resulting Locale
     */
    private static void assertValidToLocale(final String localeString, final String language, final String country,
            final String variant) {
        final var locale = LocaleUtils.toLocale(localeString);
        assertNotNull(locale, "valid locale");
        assertEquals(language, locale.getLanguage());
        assertEquals(country, locale.getCountry());
        assertEquals(variant, locale.getVariant());
    }

    /**
     * Test toLocale() method.
     */
    @Test
    void testToLocale_1Part() {
        assertNull(LocaleUtils.toLocale(null));

        assertValidToLocale("us");
        assertValidToLocale("fr");
        assertValidToLocale("de");
        assertValidToLocale("zh");
        // Valid format but lang doesn't exist, should make instance anyway
        assertValidToLocale("qq");
        // LANG-941: JDK 8 introduced the empty locale as one of the default locales
        assertValidToLocale("");

        try {
            LocaleUtils.toLocale("Us");
            fail("Should fail if not lowercase");
        } catch (final IllegalArgumentException iae) {
        }
        try {
            LocaleUtils.toLocale("US");
            fail("Should fail if not lowercase");
        } catch (final IllegalArgumentException iae) {
        }
        try {
            LocaleUtils.toLocale("uS");
            fail("Should fail if not lowercase");
        } catch (final IllegalArgumentException iae) {
        }
        try {
            LocaleUtils.toLocale("u#");
            fail("Should fail if not lowercase");
        } catch (final IllegalArgumentException iae) {
        }

        try {
            LocaleUtils.toLocale("u");
            fail("Must be 2 chars if less than 5");
        } catch (final IllegalArgumentException iae) {
        }

        try {
            LocaleUtils.toLocale("uu_U");
            fail("Must be 2 chars if less than 5");
        } catch (final IllegalArgumentException iae) {
        }
    }

    /**
     * Test toLocale() method.
     */
    @Test
    void testToLocale_2Part() {
        assertValidToLocale("us_EN", "us", "EN");
        // valid though doesn't exist
        assertValidToLocale("us_ZH", "us", "ZH");

        try {
            LocaleUtils.toLocale("us-EN");
            fail("Should fail as not underscore");
        } catch (final IllegalArgumentException iae) {
        }
        try {
            LocaleUtils.toLocale("us_En");
            fail("Should fail second part not uppercase");
        } catch (final IllegalArgumentException iae) {
        }
        try {
            LocaleUtils.toLocale("us_en");
            fail("Should fail second part not uppercase");
        } catch (final IllegalArgumentException iae) {
        }
        try {
            LocaleUtils.toLocale("us_eN");
            fail("Should fail second part not uppercase");
        } catch (final IllegalArgumentException iae) {
        }
        try {
            LocaleUtils.toLocale("uS_EN");
            fail("Should fail first part not lowercase");
        } catch (final IllegalArgumentException iae) {
        }
        try {
            LocaleUtils.toLocale("us_E3");
            fail("Should fail second part not uppercase");
        } catch (final IllegalArgumentException iae) {
        }
    }

    /**
     * Test toLocale() method.
     */
    @Test
    void testToLocale_3Part() {
        assertValidToLocale("us_EN_A", "us", "EN", "A");
        // this isn't pretty, but was caused by a jdk bug it seems
        // http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=4210525
        assertValidToLocale("us_EN_a", "us", "EN", "a");
        assertValidToLocale("us_EN_SFsafdFDsdfF", "us", "EN", "SFsafdFDsdfF");

        try {
            LocaleUtils.toLocale("us_EN-a");
            fail("Should fail as not underscore");
        } catch (final IllegalArgumentException iae) {
        }
        try {
            LocaleUtils.toLocale("uu_UU_");
            fail("Must be 3, 5 or 7+ in length");
        } catch (final IllegalArgumentException iae) {
        }
    }

    /**
     * Test for 3-chars locale, further details at LANG-915
     */
    @Test
    void testThreeCharsLocale() {
        for (final String str : Arrays.asList("udm", "tet")) {
            final var locale = LocaleUtils.toLocale(str);
            assertNotNull(locale);
            assertEquals(str, locale.getLanguage());
            assertTrue(MoreStrings.isBlank(locale.getCountry()));
            assertEquals(new Locale(str), locale);
        }
    }

    /**
     * Tests #LANG-328 - only language+variant
     */
    @Test
    void testLang328() {
        assertValidToLocale("fr__P", "fr", "", "P");
        assertValidToLocale("fr__POSIX", "fr", "", "POSIX");
    }

    @Test
    void testLanguageAndUNM49Numeric3AreaCodeLang1312() {
        assertValidToLocale("en_001", "en", "001");
        assertValidToLocale("en_150", "en", "150");
        assertValidToLocale("ar_001", "ar", "001");

        // LANG-1312
        assertValidToLocale("en_001_GB", "en", "001", "GB");
        assertValidToLocale("en_150_US", "en", "150", "US");
    }

    /**
     * Tests #LANG-865, strings starting with an underscore.
     */
    @Test
    void testLang865() {
        assertValidToLocale("_GB", "", "GB", "");
        assertValidToLocale("_GB_P", "", "GB", "P");
        assertValidToLocale("_GB_POSIX", "", "GB", "POSIX");
        try {
            LocaleUtils.toLocale("_G");
            fail("Must be at least 3 chars if starts with underscore");
        } catch (final IllegalArgumentException iae) {
        }
        try {
            LocaleUtils.toLocale("_Gb");
            fail("Must be uppercase if starts with underscore");
        } catch (final IllegalArgumentException iae) {
        }
        try {
            LocaleUtils.toLocale("_gB");
            fail("Must be uppercase if starts with underscore");
        } catch (final IllegalArgumentException iae) {
        }
        try {
            LocaleUtils.toLocale("_1B");
            fail("Must be letter if starts with underscore");
        } catch (final IllegalArgumentException iae) {
        }
        try {
            LocaleUtils.toLocale("_G1");
            fail("Must be letter if starts with underscore");
        } catch (final IllegalArgumentException iae) {
        }
        try {
            LocaleUtils.toLocale("_GB_");
            fail("Must be at least 5 chars if starts with underscore");
        } catch (final IllegalArgumentException iae) {
        }
        try {
            LocaleUtils.toLocale("_GBAP");
            fail("Must have underscore after the country if starts with underscore and is at least 5 chars");
        } catch (final IllegalArgumentException iae) {
        }
    }

    @Test
    void testParseAllLocales() {
        final var locales = Locale.getAvailableLocales();
        var failures = 0;
        for (final Locale l : locales) {
            // Check if it's possible to recreate the Locale using just the standard
            // constructor
            final var locale = new Locale(l.getLanguage(), l.getCountry(), l.getVariant());
            if (l.equals(locale)) { // it is possible for LocaleUtils.toLocale to handle these
                                    // Locales
                var str = l.toString();
                // Look for the script/extension suffix
                var suff = str.indexOf("_#");
                if (suff == -1) {
                    suff = str.indexOf("#");
                }
                if (suff >= 0) { // we have a suffix
                    try {
                        LocaleUtils.toLocale(str); // should cause IAE
                        System.out.println("Should not have parsed: " + str);
                        failures++;
                        continue; // try next Locale
                    } catch (final IllegalArgumentException iae) {
                        // expected; try without suffix
                        str = str.substring(0, suff);
                    }
                }
                final var loc = LocaleUtils.toLocale(str);
                if (!l.equals(loc)) {
                    System.out.println("Failed to parse: " + str);
                    failures++;
                }
            }
        }
        if (failures > 0) {
            fail("Failed " + failures + " test(s)");
        }
    }
}
