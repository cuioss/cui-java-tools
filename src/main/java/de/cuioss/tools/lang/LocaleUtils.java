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

import de.cuioss.tools.base.Preconditions;
import lombok.experimental.UtilityClass;

import java.util.Locale;

/**
 * <p>
 * Operations to help when working with a {@link Locale}.
 * </p>
 *
 * <p>
 * This class tries to handle {@code null} input gracefully. An exception will
 * not be thrown for a {@code null} input. Each method documents its behavior in
 * more detail.
 * </p>
 *
 * @author <a href="https://github.com/apache/commons-lang/blob/master/src/main/java/org/apache/commons/lang3/LocaleUtils.java">...</a>
 */
@UtilityClass
public class LocaleUtils {

    private static final String INVALID_LOCALE_FORMAT = "Invalid locale format: ";

    /**
     * <p>
     * Converts a String to a Locale.
     * </p>
     *
     * <p>
     * This method takes the string format of a locale and creates the locale object
     * from it.
     * </p>
     *
     * <pre>
     *   LocaleUtils.toLocale("")           = new Locale("", "")
     *   LocaleUtils.toLocale("en")         = new Locale("en", "")
     *   LocaleUtils.toLocale("en_GB")      = new Locale("en", "GB")
     *   LocaleUtils.toLocale("en_GB_xxx")  = new Locale("en", "GB", "xxx")   (#)
     * </pre>
     *
     * <p>
     * This method validates the input strictly. The language code must be
     * lowercase. The country code must be uppercase. The separator must be an
     * underscore. The length must be correct.
     * </p>
     *
     * <p>
     * Note: This implementation uses the deprecated {@link Locale} constructor for
     * backward compatibility with existing code that relies on its more lenient
     * validation rules, particularly for variants. Future versions may migrate to
     * {@link Locale.Builder} which enforces stricter rules.
     * </p>
     *
     * @param str the locale String to convert, null returns null
     * @return a Locale, null if null input
     * @throws IllegalArgumentException if the string is an invalid format
     * @see Locale#forLanguageTag(String)
     */
    public static Locale toLocale(final String str) {
        if (null == str) {
            return null;
        }
        return toLocaleInternal(str);
    }

    private static Locale toLocaleInternal(final String str) {
        if (str.isEmpty()) {
            return new Locale("", "");
        }
        Preconditions.checkArgument(!str.contains("#"), INVALID_LOCALE_FORMAT + str);

        if (str.startsWith("_")) {
            return handleUnderscorePrefixedLocale(str);
        }

        if (!str.contains("_")) {
            return handleSimpleLocale(str);
        }

        final var parts = str.split("_", 3);
        try {
            return switch (parts.length) {
                case 1 -> handleSinglePart(parts[0]);
                case 2 -> handleTwoParts(parts[0], parts[1]);
                case 3 -> handleThreeParts(str, parts);
                default -> throw new IllegalArgumentException(INVALID_LOCALE_FORMAT + str);
            };
        } catch (final IllegalArgumentException iae) {
            throw new IllegalArgumentException(INVALID_LOCALE_FORMAT + str, iae);
        }
    }

    private static Locale handleUnderscorePrefixedLocale(final String str) {
        Preconditions.checkArgument(str.length() >= 3, "Must be at least 3 chars if starts with underscore");
        Preconditions.checkArgument(!(str.length() >= 5 && !str.substring(3).startsWith("_")),
                "Must have underscore after the country if starts with underscore and is at least 5 chars");
        Preconditions.checkArgument(str.length() != 4, "Must be at least 5 chars if starts with underscore");

        final var parts = str.split("_", 3);
        if (parts.length == 2) {
            validateCountryCode(parts[1]);
            return new Locale("", parts[1]);
        }
        if (parts.length == 3) {
            validateCountryCode(parts[1]);
            return new Locale("", parts[1], parts[2]);
        }
        throw new IllegalArgumentException(INVALID_LOCALE_FORMAT + str);
    }

    private static Locale handleSimpleLocale(final String str) {
        Preconditions.checkArgument(str.length() == 2 || str.length() == 3, "Must be 2 chars if less than 5");
        Preconditions.checkArgument(str.equals(str.toLowerCase()), INVALID_LOCALE_FORMAT + str);
        return new Locale(str);
    }

    private static Locale handleSinglePart(final String language) {
        return new Locale(language.toLowerCase());
    }

    private static Locale handleTwoParts(final String language, final String country) {
        validateLanguageCode(language);
        if (country.matches("\\d{3}")) {
            return new Locale(language, country);
        }
        validateCountryCode(country);
        if (language.isEmpty()) {
            return new Locale("", country);
        }
        return new Locale(language, country);
    }

    private static Locale handleThreeParts(final String str, final String[] parts) {
        Preconditions.checkArgument(str.length() == 3 || str.length() == 5 || str.length() >= 7,
                "Must be 3, 5 or 7+ in length");
        validateLanguageCode(parts[0]);
        
        if (parts[1].isEmpty() && !parts[2].isEmpty()) {
            return new Locale(parts[0], "", parts[2]);
        }
        if (parts[1].matches("\\d{3}")) {
            return new Locale(parts[0], parts[1], parts[2]);
        }
        validateCountryCode(parts[1]);
        return new Locale(parts[0], parts[1], parts[2]);
    }

    private static void validateLanguageCode(final String language) {
        Preconditions.checkArgument(language.equals(language.toLowerCase()), "Language code must be lowercase");
    }

    private static void validateCountryCode(final String country) {
        Preconditions.checkArgument(country.equals(country.toUpperCase()) && country.matches("[A-Z]{2}"),
                "Country code must be uppercase");
    }
}
