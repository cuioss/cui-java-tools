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
            return new Locale.Builder().build();
        }
        Preconditions.checkArgument(!str.contains("#"), INVALID_LOCALE_FORMAT + str);

        // Handle special case for string starting with underscore
        if (str.startsWith("_")) {
            Preconditions.checkArgument(str.length() >= 3, "Must be at least 3 chars if starts with underscore");
            Preconditions.checkArgument(!(str.length() >= 5 && !str.substring(3).startsWith("_")),
                    "Must have underscore after the country if starts with underscore and is at least 5 chars");
            Preconditions.checkArgument(str.length() != 4, "Must be at least 5 chars if starts with underscore");

            final var parts = str.split("_", 3);
            // For _GB format
            if (parts.length == 2) {
                Preconditions.checkArgument(parts[1].matches("[A-Z]{2}"), "Must be uppercase if starts with underscore");
                return new Locale.Builder().setRegion(parts[1]).build();
            }
            // For _GB_VARIANT format
            if (parts.length == 3) {
                Preconditions.checkArgument(parts[1].matches("[A-Z]{2}"), "Must be uppercase if starts with underscore");
                // Use legacy constructor for backwards compatibility with variants
                return new Locale("", parts[1], parts[2]);
            }
            throw new IllegalArgumentException(INVALID_LOCALE_FORMAT + str);
        }

        // Handle a special case for single lowercase language
        if (!str.contains("_")) {
            Preconditions.checkArgument(str.length() == 2 || str.length() == 3, "Must be 2 chars if less than 5");
            Preconditions.checkArgument(str.equals(str.toLowerCase()), INVALID_LOCALE_FORMAT + str);
            return new Locale.Builder().setLanguage(str).build();
        }

        final var parts = str.split("_", 3);
        try {
            return switch (parts.length) {
                case 1 -> new Locale.Builder().setLanguage(parts[0].toLowerCase()).build();
                case 2 -> {
                    Preconditions.checkArgument(parts[0].equals(parts[0].toLowerCase()), "Language code must be lowercase");
                    if (parts[1].matches("\\d{3}")) {
                        yield new Locale.Builder()
                                .setLanguage(parts[0])
                                .setRegion(parts[1])
                                .build(); // Handle numeric country codes
                    }
                    Preconditions.checkArgument(parts[1].equals(parts[1].toUpperCase()) && parts[1].matches("[A-Z]{2}"),
                            "Country code must be uppercase");
                    if (parts[0].isEmpty()) {
                        yield new Locale.Builder().setRegion(parts[1]).build();
                    }
                    yield new Locale.Builder()
                            .setLanguage(parts[0])
                            .setRegion(parts[1])
                            .build();
                }
                case 3 -> {
                    Preconditions.checkArgument(str.length() == 3 || str.length() == 5 || str.length() >= 7,
                            "Must be 3, 5 or 7+ in length");
                    Preconditions.checkArgument(parts[0].equals(parts[0].toLowerCase()),
                            "Language code must be lowercase");
                    if (parts[1].isEmpty() && !parts[2].isEmpty()) {
                        // Use legacy constructor for backwards compatibility with variants
                        yield new Locale(parts[0], "", parts[2]); // Handle double underscore variants
                    }
                    if (parts[1].matches("\\d{3}")) {
                        // Use legacy constructor for backwards compatibility with variants
                        yield new Locale(parts[0], parts[1], parts[2]); // Handle numeric country codes with variants
                    }
                    Preconditions.checkArgument(parts[1].equals(parts[1].toUpperCase()) && parts[1].matches("[A-Z]{2}"),
                            "Country code must be uppercase");
                    // Use legacy constructor for backwards compatibility with variants
                    yield new Locale(parts[0], parts[1], parts[2]);
                }
                default -> throw new IllegalArgumentException(INVALID_LOCALE_FORMAT + str);
            };
        } catch (final IllegalArgumentException iae) {
            throw new IllegalArgumentException(INVALID_LOCALE_FORMAT + str, iae);
        }
    }

}
