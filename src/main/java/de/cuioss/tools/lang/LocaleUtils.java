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

import de.cuioss.tools.string.MoreStrings;
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
     *   LocaleUtils.toLocale("en_001")     = new Locale("en", "001")
     *   LocaleUtils.toLocale("en_GB_xxx")  = new Locale("en", "GB", "xxx")   (#)
     * </pre>
     *
     * <p>
     * This method validates the input strictly. The language code must be
     * lowercase. The country code must be uppercase. The separator must be an
     * underscore. The length must be correct.
     * </p>
     *
     * @param str the locale String to convert, null returns null
     * @return a Locale, null if null input
     * @throws IllegalArgumentException if the string is an invalid format
     * @see Locale#forLanguageTag(String)
     */
    @SuppressWarnings("squid:S3776") // owolff: Original code
    public static Locale toLocale(final String str) {
        if (str == null) {
            return null;
        }
        return toLocaleInternal(str);
    }

    private static Locale toLocaleInternal(final String str) {
        if (str.isEmpty()) {
            return new Locale.Builder().build();
        }
        if (str.contains("#")) {
            throw new IllegalArgumentException(INVALID_LOCALE_FORMAT + str);
        }

        // Handle special case for string starting with underscore
        if (str.startsWith("_")) {
            if (str.length() < 3) {
                throw new IllegalArgumentException("Must be at least 3 chars if starts with underscore");
            }
            if (str.length() >= 5 && !str.substring(3).startsWith("_")) {
                throw new IllegalArgumentException("Must have underscore after the country if starts with underscore and is at least 5 chars");
            }
            if (str.length() == 4) {
                throw new IllegalArgumentException("Must be at least 5 chars if starts with underscore");
            }
            final var parts = str.split("_", 3);
            // For _GB format
            if (parts.length == 2) {
                if (!parts[1].matches("[A-Z]{2}")) {
                    throw new IllegalArgumentException("Must be uppercase if starts with underscore");
                }
                return new Locale.Builder().setRegion(parts[1]).build();
            }
            // For _GB_VARIANT format
            if (parts.length == 3) {
                if (!parts[1].matches("[A-Z]{2}")) {
                    throw new IllegalArgumentException("Must be uppercase if starts with underscore");
                }
                // Use legacy constructor for backwards compatibility with variants
                return new Locale("", parts[1], parts[2]);
            }
            throw new IllegalArgumentException(INVALID_LOCALE_FORMAT + str);
        }

        // Handle special case for single lowercase language
        if (!str.contains("_")) {
            if (str.length() != 2 && str.length() != 3) {
                throw new IllegalArgumentException("Must be 2 chars if less than 5");
            }
            if (!str.equals(str.toLowerCase())) {
                throw new IllegalArgumentException(INVALID_LOCALE_FORMAT + str);
            }
            return new Locale.Builder().setLanguage(str).build();
        }

        final var parts = str.split("_", 3);
        try {
            return switch (parts.length) {
                case 1 -> new Locale.Builder().setLanguage(parts[0].toLowerCase()).build();
                case 2 -> {
                    if (!parts[0].equals(parts[0].toLowerCase())) {
                        throw new IllegalArgumentException("Language code must be lowercase");
                    }
                    if (parts[1].matches("\\d{3}")) {
                        yield new Locale.Builder()
                            .setLanguage(parts[0])
                            .setRegion(parts[1])
                            .build(); // Handle numeric country codes
                    }
                    if (!parts[1].equals(parts[1].toUpperCase()) || !parts[1].matches("[A-Z]{2}")) {
                        throw new IllegalArgumentException("Country code must be uppercase");
                    }
                    if (parts[0].isEmpty()) {
                        yield new Locale.Builder().setRegion(parts[1]).build();
                    }
                    yield new Locale.Builder()
                        .setLanguage(parts[0])
                        .setRegion(parts[1])
                        .build();
                }
                case 3 -> {
                    if (str.length() != 3 && str.length() != 5 && str.length() < 7) {
                        throw new IllegalArgumentException("Must be 3, 5 or 7+ in length");
                    }
                    if (!parts[0].equals(parts[0].toLowerCase())) {
                        throw new IllegalArgumentException("Language code must be lowercase");
                    }
                    if (parts[1].isEmpty() && !parts[2].isEmpty()) {
                        // Use legacy constructor for backwards compatibility with variants
                        yield new Locale(parts[0], "", parts[2]); // Handle double underscore variants
                    }
                    if (parts[1].matches("\\d{3}")) {
                        // Use legacy constructor for backwards compatibility with variants
                        yield new Locale(parts[0], parts[1], parts[2]); // Handle numeric country codes with variants
                    }
                    if (!parts[1].equals(parts[1].toUpperCase()) || !parts[1].matches("[A-Z]{2}")) {
                        throw new IllegalArgumentException("Country code must be uppercase");
                    }
                    // Use legacy constructor for backwards compatibility with variants
                    yield new Locale(parts[0], parts[1], parts[2]);
                }
                default -> throw new IllegalArgumentException(INVALID_LOCALE_FORMAT + str);
            };
        } catch (final IllegalArgumentException iae) {
            throw new IllegalArgumentException(INVALID_LOCALE_FORMAT + str, iae);
        }
    }

    /**
     * Tries to parse a locale from the given String.
     *
     * @param str the String to parse a locale from.
     * @return a Locale instance parsed from the given String.
     * @throws IllegalArgumentException if the given String can not be parsed.
     */
    private static Locale parseLocale(final String str) {
        final var parts = str.split("_", 3);
        try {
            return switch (parts.length) {
                case 1 -> new Locale.Builder().setLanguage(parts[0]).build();
                case 2 -> new Locale.Builder().setLanguage(parts[0]).setRegion(parts[1]).build();
                case 3 -> new Locale.Builder().setLanguage(parts[0]).setRegion(parts[1]).setVariant(parts[2]).build();
                default -> throw new IllegalArgumentException(INVALID_LOCALE_FORMAT + str);
            };
        } catch (final IllegalArgumentException iae) {
            throw new IllegalArgumentException(INVALID_LOCALE_FORMAT + str, iae);
        }
    }

    /**
     * Checks whether the given String is a ISO 639 compliant language code.
     *
     * @param str the String to check.
     * @return true, if the given String is a ISO 639 compliant language code.
     */
    private static boolean isISO639LanguageCode(final String str) {
        return str.length() >= 2 && str.length() <= 3;
    }

    /**
     * Checks whether the given String is a ISO 3166 alpha-2 country code.
     *
     * @param str the String to check
     * @return true, is the given String is a ISO 3166 compliant country code.
     */
    private static boolean isISO3166CountryCode(final String str) {
        return str.length() == 2 && str.equals(str.toUpperCase());
    }

    /**
     * Checks whether the given String is a UN M.49 numeric area code.
     *
     * @param str the String to check
     * @return true, is the given String is a UN M.49 numeric area code.
     */
    private static boolean isNumericAreaCode(final String str) {
        return str.length() == 3 && str.matches("\\d{3}");
    }
}
