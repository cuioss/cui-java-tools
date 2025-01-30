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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Unit tests for {@link LocaleUtils}. Tests the conversion of strings to Locale objects
 * with various formats and validates the handling of invalid inputs.
 */
class LocaleUtilsTest {

    @Test
    void shouldHandleNullInput() {
        assertNull(LocaleUtils.toLocale(null));
    }

    @ParameterizedTest
    @ValueSource(strings = {"us", "fr", "de", "zh", "qq", ""})
    void shouldHandleValidLanguageCodes(String language) {
        var locale = LocaleUtils.toLocale(language);
        assertNotNull(locale, "Should create valid locale");
        assertEquals(language, locale.getLanguage());
        assertTrue(locale.getCountry().isEmpty(), "Country should be empty");
        assertTrue(locale.getVariant().isEmpty(), "Variant should be empty");
    }

    @ParameterizedTest
    @ValueSource(strings = {"Us", "US", "uS", "u#"})
    void shouldRejectInvalidCaseInLanguageCode(String invalidLanguage) {
        assertThrows(IllegalArgumentException.class, () -> LocaleUtils.toLocale(invalidLanguage),
                "Should fail if not lowercase");
    }

    @ParameterizedTest
    @ValueSource(strings = {"u", "uu_U"})
    void shouldRejectInvalidLengthLanguageCode(String invalidLanguage) {
        assertThrows(IllegalArgumentException.class, () -> LocaleUtils.toLocale(invalidLanguage),
                "Must be 2 chars if less than 5");
    }

    @ParameterizedTest
    @CsvSource({
            "us_EN,us,EN",
            "us_ZH,us,ZH"
    })
    void shouldHandleValidLanguageCountryCombinations(String localeString, String language, String country) {
        var locale = LocaleUtils.toLocale(localeString);
        assertNotNull(locale, "Should create valid locale");
        assertEquals(language, locale.getLanguage());
        assertEquals(country, locale.getCountry());
        assertTrue(locale.getVariant().isEmpty(), "Variant should be empty");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "us-EN",    // Invalid separator
            "us_En",    // Invalid country case
            "us_en",    // Invalid country case
            "us_eN",    // Invalid country case
            "uS_EN",    // Invalid language case
            "us_E3"     // Invalid country format
    })
    void shouldRejectInvalidLanguageCountryCombinations(String invalidLocale) {
        assertThrows(IllegalArgumentException.class, () -> LocaleUtils.toLocale(invalidLocale));
    }

    @ParameterizedTest
    @CsvSource({
            "us_EN_A,us,EN,A",
            "us_EN_a,us,EN,a",
            "us_EN_variant,us,EN,variant"
    })
    void shouldHandleValidLanguageCountryVariantCombinations(String localeString, String language, String country, String variant) {
        var locale = LocaleUtils.toLocale(localeString);
        assertNotNull(locale, "Should create valid locale");
        assertEquals(language, locale.getLanguage());
        assertEquals(country, locale.getCountry());
        assertEquals(variant, locale.getVariant());
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "us_EN-a",  // Invalid separator
            "uu_UU_"    // Invalid length
    })
    void shouldRejectInvalidLanguageCountryVariantCombinations(String invalidLocale) {
        assertThrows(IllegalArgumentException.class, () -> LocaleUtils.toLocale(invalidLocale));
    }

    @ParameterizedTest
    @CsvSource(value = {
            "_EN,,EN,",
            "_EN_variant,,EN,variant"
    }, nullValues = "")
    void shouldHandleValidCountryOnlyCombinations(String localeString, String language, String country, String variant) {
        var locale = LocaleUtils.toLocale(localeString);
        assertNotNull(locale, "Should create valid locale");
        assertTrue(locale.getLanguage().isEmpty());
        assertEquals(country, locale.getCountry());
        assertEquals(variant != null ? variant : "", locale.getVariant());
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "_En",      // Invalid country case
            "_",        // Missing country
            "__",       // Missing country
            "_En_",     // Invalid format
            "_eN_var"   // Invalid country case
    })
    void shouldRejectInvalidCountryOnlyCombinations(String invalidLocale) {
        assertThrows(IllegalArgumentException.class, () -> LocaleUtils.toLocale(invalidLocale));
    }

    @ParameterizedTest
    @CsvSource(value = {
            "de_123,de,123,",
            "de_123_variant,de,123,variant"
    }, nullValues = "")
    void shouldHandleNumericCountryCodes(String localeString, String language, String country, String variant) {
        var locale = LocaleUtils.toLocale(localeString);
        assertNotNull(locale, "Should create valid locale");
        assertEquals(language, locale.getLanguage());
        assertEquals(country, locale.getCountry());
        assertEquals(variant != null ? variant : "", locale.getVariant());
    }

    @ParameterizedTest
    @CsvSource({
            "de__variant,de,,variant"
    })
    void shouldHandleEmptyCountryWithVariant(String localeString, String language, String country, String variant) {
        var locale = LocaleUtils.toLocale(localeString);
        assertNotNull(locale, "Should create valid locale");
        assertEquals(language, locale.getLanguage());
        assertTrue(locale.getCountry().isEmpty());
        assertEquals(variant, locale.getVariant());
    }
}
