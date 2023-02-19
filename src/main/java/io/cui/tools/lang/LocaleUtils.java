package io.cui.tools.lang;

import java.util.Locale;

import io.cui.tools.string.MoreStrings;
import lombok.experimental.UtilityClass;

/**
 * <p>
 * Operations to assist when working with a {@link Locale}.
 * </p>
 *
 * <p>
 * This class tries to handle {@code null} input gracefully.
 * An exception will not be thrown for a {@code null} input.
 * Each method documents its behavior in more detail.
 * </p>
 *
 * @author https://github.com/apache/commons-lang/blob/master/src/main/java/org/apache/commons/lang3/LocaleUtils.java
 *
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
     * This method takes the string format of a locale and creates the
     * locale object from it.
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
     * This method validates the input strictly.
     * The language code must be lowercase.
     * The country code must be uppercase.
     * The separator must be an underscore.
     * The length must be correct.
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
        if (str.isEmpty()) { // LANG-941 - JDK 8 introduced an empty locale where all fields are
                             // blank
            return new Locale(MoreStrings.EMPTY, MoreStrings.EMPTY);
        }
        if (str.contains("#")) { // LANG-879 - Cannot handle Java 7 script & extensions
            throw new IllegalArgumentException(INVALID_LOCALE_FORMAT + str);
        }
        final var len = str.length();
        if (len < 2) {
            throw new IllegalArgumentException(INVALID_LOCALE_FORMAT + str);
        }
        final var ch0 = str.charAt(0);
        if (ch0 == '_') {
            if (len < 3) {
                throw new IllegalArgumentException(INVALID_LOCALE_FORMAT + str);
            }
            final var ch1 = str.charAt(1);
            final var ch2 = str.charAt(2);
            if (!Character.isUpperCase(ch1) || !Character.isUpperCase(ch2)) {
                throw new IllegalArgumentException(INVALID_LOCALE_FORMAT + str);
            }
            if (len == 3) {
                return new Locale(MoreStrings.EMPTY, str.substring(1, 3));
            }
            if (len < 5 || str.charAt(3) != '_') {
                throw new IllegalArgumentException(INVALID_LOCALE_FORMAT + str);
            }
            return new Locale(MoreStrings.EMPTY, str.substring(1, 3), str.substring(4));
        }

        return parseLocale(str);
    }

    /**
     * Tries to parse a locale from the given String.
     *
     * @param str the String to parse a locale from.
     *
     * @return a Locale instance parsed from the given String.
     * @throws IllegalArgumentException if the given String can not be parsed.
     */
    private static Locale parseLocale(final String str) {
        if (isISO639LanguageCode(str)) {
            return new Locale(str);
        }

        final var segments = str.split("_", -1);
        final var language = segments[0];
        if (segments.length == 2) {
            final var country = segments[1];
            if (isISO639LanguageCode(language) && isISO3166CountryCode(country) ||
                    isNumericAreaCode(country)) {
                return new Locale(language, country);
            }
        } else if (segments.length == 3) {
            final var country = segments[1];
            final var variant = segments[2];
            if (isISO639LanguageCode(language) &&
                    (country.isEmpty() || isISO3166CountryCode(country) || isNumericAreaCode(country)) &&
                    !variant.isEmpty()) {
                return new Locale(language, country, variant);
            }
        }
        throw new IllegalArgumentException(INVALID_LOCALE_FORMAT + str);
    }

    /**
     * Checks whether the given String is a ISO 639 compliant language code.
     *
     * @param str the String to check.
     *
     * @return true, if the given String is a ISO 639 compliant language code.
     */
    private static boolean isISO639LanguageCode(final String str) {
        return MoreStrings.isAllLowerCase(str) && (str.length() == 2 || str.length() == 3);
    }

    /**
     * Checks whether the given String is a ISO 3166 alpha-2 country code.
     *
     * @param str the String to check
     *
     * @return true, is the given String is a ISO 3166 compliant country code.
     */
    private static boolean isISO3166CountryCode(final String str) {
        return MoreStrings.isAllUpperCase(str) && str.length() == 2;
    }

    /**
     * Checks whether the given String is a UN M.49 numeric area code.
     *
     * @param str the String to check
     *
     * @return true, is the given String is a UN M.49 numeric area code.
     */
    private static boolean isNumericAreaCode(final String str) {
        return MoreStrings.isNumeric(str) && str.length() == 3;
    }
}
