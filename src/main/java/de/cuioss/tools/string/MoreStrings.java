/*
 * Copyright 2023 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.tools.string;

import de.cuioss.tools.logging.CuiLogger;
import lombok.NonNull;
import lombok.experimental.UtilityClass;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;

import static de.cuioss.tools.base.Preconditions.checkArgument;

/**
 * Provides enhanced String handling utilities focusing on null-safety, performance,
 * and common string manipulation tasks. This class serves as a lightweight alternative
 * to larger utility libraries while maintaining high standards for code quality
 * and usability.
 *
 * <h2>Key Features</h2>
 * <ul>
 *   <li>Null-safe string operations with consistent behavior</li>
 *   <li>Efficient string formatting with improved null handling</li>
 *   <li>Comprehensive string validation and transformation utilities</li>
 *   <li>Performance-optimized string manipulation methods</li>
 *   <li>Consistent error handling and validation</li>
 * </ul>
 *
 * <h2>Method Categories</h2>
 * <ol>
 *   <li><b>Null and Empty Handling</b>
 *     <ul>
 *       <li>{@link #nullToEmpty(String)} - Convert null to empty string</li>
 *       <li>{@link #emptyToNull(String)} - Convert empty string to null</li>
 *       <li>{@link #isEmpty(CharSequence)} - Check if string is null or empty</li>
 *       <li>{@link #isBlank(CharSequence)} - Check if string is null, empty, or whitespace</li>
 *     </ul>
 *   </li>
 *   <li><b>String Validation</b>
 *     <ul>
 *       <li>{@link #isAllLowerCase(CharSequence)} - Check for lowercase content</li>
 *       <li>{@link #isAllUpperCase(CharSequence)} - Check for uppercase content</li>
 *       <li>{@link #isNumeric(CharSequence)} - Check for numeric content</li>
 *       <li>{@link #hasNonWhitespaceChar(CharSequence)} - Check for non-whitespace content</li>
 *     </ul>
 *   </li>
 *   <li><b>String Transformation</b>
 *     <ul>
 *       <li>{@link #unquote(String)} - Remove surrounding quotes</li>
 *       <li>{@link #trimOrNull(String)} - Trim or return null</li>
 *       <li>{@link #stripEnd(String, String)} - Remove characters from end</li>
 *       <li>{@link #leftPad(String, int)} - Add padding to left side</li>
 *     </ul>
 *   </li>
 *   <li><b>String Search and Manipulation</b>
 *     <ul>
 *       <li>{@link #indexOf(CharSequence, int)} - Find character position</li>
 *       <li>{@link #countMatches(CharSequence, CharSequence)} - Count occurrences</li>
 *       <li>{@link #repeat(char, int)} - Repeat character</li>
 *       <li>{@link #ensureEndsWith(String, String)} - Ensure suffix presence</li>
 *     </ul>
 *   </li>
 *   <li><b>String Formatting</b>
 *     <ul>
 *       <li>{@link #lenientFormat(String, Object...)} - Safe string formatting</li>
 *     </ul>
 *   </li>
 * </ol>
 *
 * <h2>Usage Examples</h2>
 *
 * <h3>1. Null-Safe String Operations</h3>
 * <pre>
 * // Safe null handling
 * String nullString = null;
 * assertEquals("", nullToEmpty(nullString));
 * assertEquals("default", firstNonEmpty(nullString, "default").orElse(""));
 *
 * // Safe empty handling
 * String emptyString = "";
 * assertTrue(isEmpty(emptyString));
 * assertTrue(isBlank("   "));
 * assertFalse(isEmpty("  not empty  "));
 * </pre>
 *
 * <h3>2. String Validation</h3>
 * <pre>
 * // Case validation
 * assertTrue(isAllLowerCase("lowercase"));
 * assertTrue(isAllUpperCase("UPPERCASE"));
 * assertFalse(isAllLowerCase("Mixed"));
 *
 * // Content validation
 * assertTrue(isNumeric("12345"));
 * assertTrue(hasNonWhitespaceChar("  text  "));
 * assertFalse(isNumeric("12.34")); // decimals not considered numeric
 * </pre>
 *
 * <h3>3. String Transformation</h3>
 * <pre>
 * // Quoting
 * assertEquals("text", unquote("'text'"));
 * assertEquals("text", unquote("\"text\""));
 *
 * // Padding
 * assertEquals("  text", leftPad("text", 6));
 * assertEquals("00123", leftPad("123", 5, '0'));
 *
 * // Stripping
 * assertEquals("123", stripEnd("123.00", ".0"));
 * assertEquals("text", stripEnd("text   ", null));
 * </pre>
 *
 * <h3>4. String Search and Manipulation</h3>
 * <pre>
 * // Searching
 * assertEquals(2, countMatches("banana", "a"));
 * assertEquals(1, indexOf("hello", 'e'));
 *
 * // Manipulation
 * assertEquals("***", repeat('*', 3));
 * assertEquals("file.txt", ensureEndsWith("file", ".txt"));
 * </pre>
 *
 * <h3>5. Safe String Formatting</h3>
 * <pre>
 * // Basic formatting
 * assertEquals("Hello, world!", lenientFormat("Hello, %s!", "world"));
 *
 * // Null argument handling
 * assertEquals("Value: null", lenientFormat("Value: %s", null));
 *
 * // Extra arguments handling
 * assertEquals("Hello! [world, extra]", lenientFormat("Hello!", "world", "extra"));
 * </pre>
 *
 * <h2>Migration Guide</h2>
 * <h3>From Apache Commons Lang StringUtils</h3>
 * <pre>
 * // Commons Lang                     // MoreStrings
 * StringUtils.isEmpty(str)            isEmpty(str)
 * StringUtils.isBlank(str)           isBlank(str)
 * StringUtils.defaultString(str, "") nullToEmpty(str)
 * StringUtils.strip(str)             trimOrNull(str)
 * StringUtils.leftPad(str, n)        leftPad(str, n)
 * </pre>
 *
 * <h3>From Google Guava Strings</h3>
 * <pre>
 * // Guava                           // MoreStrings
 * Strings.nullToEmpty(str)           nullToEmpty(str)
 * Strings.emptyToNull(str)           emptyToNull(str)
 * Strings.repeat(str, n)             repeat(str.charAt(0), n) // for single char
 * Strings.lenientFormat(str, args)   lenientFormat(str, args)
 * </pre>
 *
 * <h2>Performance Considerations</h2>
 * <ul>
 *   <li><b>String Creation</b>: Methods minimize object creation by reusing constants like {@link #EMPTY} and {@link #SPACE}</li>
 *   <li><b>StringBuilder Usage</b>: String concatenation operations use StringBuilder for better performance</li>
 *   <li><b>Early Returns</b>: Methods implement early returns for null/empty cases to avoid unnecessary processing</li>
 *   <li><b>Memory Usage</b>: The {@link #PAD_LIMIT} constant prevents excessive memory allocation in padding operations</li>
 *   <li><b>Iteration Efficiency</b>: Character iteration is optimized using direct char access instead of substring operations</li>
 *   <li><b>Null Safety</b>: Null checks are performed before string operations to prevent NPEs without sacrificing performance</li>
 * </ul>
 *
 * <h2>Thread Safety</h2>
 * <p>All methods in this class are stateless and thread-safe. They can be safely used in multi-threaded environments.</p>
 *
 * @author Oliver Wolff
 * @author Sven Haag
 *
 * @see <a href="https://github.com/apache/commons-lang/blob/master/src/main/java/org/apache/commons/lang3/StringUtils.java">Apache Commons Lang StringUtils</a>
 * @see <a href="https://github.com/google/guava/blob/master/guava/src/com/google/common/base/Strings.java">Google Guava Strings</a>
 * @see <a href="https://github.com/spring-projects/spring-framework/blob/main/spring-core/src/main/java/org/springframework/util/StringUtils.java">Spring Framework StringUtils</a>
 */
@UtilityClass
public final class MoreStrings {

    private static final CuiLogger LOGGER = new CuiLogger(MoreStrings.class);

    /**
     * The empty String {@code ""}.
     * Used as a constant to avoid creating empty strings repeatedly.
     */
    public static final String EMPTY = "";

    /**
     * A String for a space character.
     * Used for consistent space representation across the codebase.
     */
    public static final String SPACE = " ";

    /**
     * Represents a failed index search.
     * Used to indicate when a search operation finds no match.
     */
    public static final int INDEX_NOT_FOUND = -1;

    /**
     * The maximum size to which the padding constant(s) can expand.
     * This limit prevents excessive memory allocation in padding operations.
     */
    private static final int PAD_LIMIT = 8192;

    /**
     * "Unquotes" a String by removing surrounding single or double quotes if present.
     * This method is particularly useful when processing user input or configuration values
     * that may contain quoted strings.
     *
     * <h3>Examples:</h3>
     * <pre>
     * unquote(null)      = null
     * unquote("")        = ""
     * unquote("'text'")  = "text"
     * unquote("\"text\"") = "text"
     * unquote("text")    = "text"
     * </pre>
     *
     * @param original the string to unquote, may be null or empty
     * @return the unquoted String, or the original if no quotes were found or input was null/empty
     */
    public static String unquote(final String original) {
        if (isEmpty(original)) {
            return original;
        }
        if (original.startsWith("\"") && original.endsWith("\"")
                || original.startsWith("'") && original.endsWith("'")) {
            return original.substring(1, original.length() - 1);
        }
        return original;
    }

    /**
     * <p>
     * Checks if the CharSequence contains only lowercase characters.
     * </p>
     *
     * <p>
     * {@code null} will return {@code false}. An empty CharSequence (length()=0)
     * will return {@code false}.
     * </p>
     *
     * <pre>
     * MoreStrings.isAllLowerCase(null)   = false
     * MoreStrings.isAllLowerCase("")     = false
     * MoreStrings.isAllLowerCase("  ")   = false
     * MoreStrings.isAllLowerCase("abc")  = true
     * MoreStrings.isAllLowerCase("abC")  = false
     * MoreStrings.isAllLowerCase("ab c") = false
     * MoreStrings.isAllLowerCase("ab1c") = false
     * MoreStrings.isAllLowerCase("ab/c") = false
     * </pre>
     *
     * <p>
     * Inspired by Apache Commons Lang StringUtils.
     *
     * @param cs the CharSequence to check, may be null
     * @return {@code true} if only contains lowercase characters, and is non-null
     * @see <a href="https://github.com/apache/commons-lang/blob/master/src/main/java/org/apache/commons/lang3/StringUtils.java">Apache Commons Lang</a>
     */
    public static boolean isAllLowerCase(final CharSequence cs) {
        if (isEmpty(cs)) {
            return false;
        }
        final var sz = cs.length();
        for (var i = 0; i < sz; i++) {
            if (!Character.isLowerCase(cs.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    /**
     * <p>
     * Checks if the CharSequence contains only uppercase characters.
     * </p>
     *
     * <p>
     * {@code null} will return {@code false}. An empty String (length()=0) will
     * return {@code false}.
     * </p>
     *
     * <pre>
     * MoreStrings.isAllUpperCase(null)   = false
     * MoreStrings.isAllUpperCase("")     = false
     * MoreStrings.isAllUpperCase("  ")   = false
     * MoreStrings.isAllUpperCase("ABC")  = true
     * MoreStrings.isAllUpperCase("aBC")  = false
     * MoreStrings.isAllUpperCase("A C")  = false
     * MoreStrings.isAllUpperCase("A1C")  = false
     * MoreStrings.isAllUpperCase("A/C")  = false
     * </pre>
     *
     * <p>
     * Inspired by Apache Commons Lang StringUtils.
     *
     * @param cs the CharSequence to check, may be null
     * @return {@code true} if only contains uppercase characters, and is non-null
     * @see <a href="https://github.com/apache/commons-lang/blob/master/src/main/java/org/apache/commons/lang3/StringUtils.java">Apache Commons Lang</a>
     */
    public static boolean isAllUpperCase(final CharSequence cs) {
        if (isEmpty(cs)) {
            return false;
        }
        final var sz = cs.length();
        for (var i = 0; i < sz; i++) {
            if (!Character.isUpperCase(cs.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    /**
     * <p>
     * Checks if a CharSequence is empty ("") or null.
     * </p>
     *
     * <pre>
     * MoreStrings.isEmpty(null)      = true
     * MoreStrings.isEmpty("")        = true
     * MoreStrings.isEmpty(" ")       = false
     * MoreStrings.isEmpty("bob")     = false
     * MoreStrings.isEmpty("  bob  ") = false
     * </pre>
     *
     * <p>
     * Inspired by Apache Commons Lang StringUtils.
     *
     * @param cs the CharSequence to check, may be null
     * @return {@code true} if the CharSequence is empty or null
     * @see <a href="https://github.com/apache/commons-lang/blob/master/src/main/java/org/apache/commons/lang3/StringUtils.java">Apache Commons Lang</a>
     */
    public static boolean isEmpty(final CharSequence cs) {
        return cs == null || cs.isEmpty();
    }

    /**
     * <p>
     * Checks if a CharSequence is not empty ("") or null.
     * </p>
     *
     * <pre>
     * MoreStrings.isEmpty(null)      = false
     * MoreStrings.isEmpty("")        = false
     * MoreStrings.isEmpty(" ")       = true
     * </pre>
     *
     * @param cs the CharSequence to check, may be null
     * @return {@code true} if the CharSequence is not empty
     */
    public static boolean isPresent(final CharSequence cs) {
        return cs != null && !cs.isEmpty();
    }

    /**
     * <p>
     * Checks if the CharSequence contains only Unicode digits. A decimal point is
     * not a Unicode digit and returns false.
     * </p>
     *
     * <p>
     * {@code null} will return {@code false}. An empty CharSequence (length()=0)
     * will return {@code false}.
     * </p>
     *
     * <p>
     * Note that the method does not allow for a leading sign, either positive or
     * negative. Also, if a String passes the numeric test, it may still generate a
     * NumberFormatException when parsed by Integer.parseInt or Long.parseLong, e.g.
     * if the value is outside the range for int or long respectively.
     * </p>
     *
     * <pre>
     * MoreStrings.isNumeric(null)   = false
     * MoreStrings.isNumeric("")     = false
     * MoreStrings.isNumeric("  ")   = false
     * MoreStrings.isNumeric("123")  = true
     * MoreStrings.isNumeric("१२३")  = true MoreStrings.isNumeric("12 3") = false MoreStrings.isNumeric("ab2c") = false MoreStrings.isNumeric("12-3") = false MoreStrings.isNumeric("12.3") = false MoreStrings.isNumeric("-123") = false MoreStrings.isNumeric("+123") = false
     * </pre >
     *
     * <p>
     * Inspired by Apache Commons Lang StringUtils.
     * @see <a href="https://github.com/apache/commons-lang/blob/master/src/main/java/org/apache/commons/lang3/StringUtils.java#L3677">org.apache.commons.lang3.StringUtils#isNumeric</a>
     * @param cs the CharSequence to check, may be null
     * @return true if only contains digits, and is non-null
     */
    public static boolean isNumeric(final CharSequence cs) {
        if (isEmpty(cs)) {
            return false;
        }
        final var sz = cs.length();
        for (var i = 0; i < sz; i++) {
            if (!Character.isDigit(cs.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    /**
     * <p>
     * Checks if a CharSequence is empty (""), null or whitespace only.
     * </p>
     *
     * <p>
     * Whitespace is defined by {@link Character#isWhitespace(char)}.
     * </p>
     *
     * <pre>
     * MoreStrings.isBlank(null)      = true
     * MoreStrings.isBlank("")        = true
     * MoreStrings.isBlank(" ")       = true
     * MoreStrings.isBlank("bob")     = false
     * MoreStrings.isBlank("  bob  ") = false
     * </pre>
     *
     * <p>
     * Inspired by Apache Commons Lang StringUtils.
     *
     * @param cs the CharSequence to check, may be null
     * @return {@code true} if the CharSequence is null, empty or whitespace only
     * @see <a href="https://github.com/apache/commons-lang/blob/master/src/main/java/org/apache/commons/lang3/StringUtils.java">Apache Commons Lang</a>
     */
    public static boolean isBlank(final CharSequence cs) {
        final int strLen;
        if (cs == null || (strLen = cs.length()) == 0) {
            return true;
        }
        for (var i = 0; i < strLen; i++) {
            if (!Character.isWhitespace(cs.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    /**
     * {@code NOT} of {@link #isBlank(CharSequence)}.
     *
     * <p>
     * Checks if a CharSequence is not empty (""), null or contains whitespaces
     * only.
     * </p>
     *
     * <p>
     * Whitespace is defined by {@link Character#isWhitespace(char)}.
     * </p>
     *
     * <pre>
     * MoreStrings.isBlank(null)      = false
     * MoreStrings.isBlank("")        = false
     * MoreStrings.isBlank(" ")       = false
     * MoreStrings.isBlank("bob")     = true
     * MoreStrings.isBlank("  bob  ") = true
     * </pre>
     *
     * @param cs to be checked
     * @return {@code true} if the given string is no blank, {@code false} otherwise
     */
    public static boolean isNotBlank(final CharSequence cs) {
        return !isBlank(cs);
    }

    /**
     * <p>
     * Counts how many times the substring appears in the larger string.
     * </p>
     *
     * <p>
     * A {@code null} or empty ("") String input returns {@code 0}.
     * </p>
     *
     * <pre>
     * MoreStrings.countMatches(null, *)       = 0
     * MoreStrings.countMatches("", *)         = 0
     * MoreStrings.countMatches("abba", null)  = 0
     * MoreStrings.countMatches("abba", "")    = 0
     * MoreStrings.countMatches("abba", "a")   = 2
     * MoreStrings.countMatches("abba", "ab")  = 1
     * MoreStrings.countMatches("abba", "xxx") = 0
     * </pre>
     *
     *
     * <p>
     * Inspired by Apache Commons Lang StringUtils.
     *
     * @param str the CharSequence to check, may be null
     * @param sub the substring to count, may be null
     * @return the number of occurrences, 0 if either CharSequence is {@code null}
     * @see <a href="https://github.com/apache/commons-lang/blob/master/src/main/java/org/apache/commons/lang3/StringUtils.java">Apache Commons Lang</a>
     */
    public static int countMatches(final CharSequence str, final CharSequence sub) {
        if (isEmpty(str) || isEmpty(sub)) {
            return 0;
        }
        var count = 0;
        var idx = 0;
        while ((idx = indexOf(str, sub, idx)) != INDEX_NOT_FOUND) {
            count++;
            idx += sub.length();
        }
        return count;
    }

    /**
     * <p>
     * Left pad a String with spaces (' ').
     * </p>
     *
     * <p>
     * The String is padded to the size of {@code size}.
     * </p>
     *
     * <pre>
     * MoreStrings.leftPad(null, *)   = null
     * MoreStrings.leftPad("", 3)     = "   "
     * MoreStrings.leftPad("bat", 3)  = "bat"
     * MoreStrings.leftPad("bat", 5)  = "  bat"
     * MoreStrings.leftPad("bat", 1)  = "bat"
     * MoreStrings.leftPad("bat", -1) = "bat"
     * </pre>
     *
     * <p>
     * Inspired by Apache Commons Lang StringUtils.
     *
     * @param str  the String to pad out, may be null
     * @param size the size to pad to
     * @return left padded String or original String if no padding is necessary,
     * {@code null} if null String input
     * @see <a href="https://github.com/apache/commons-lang/blob/master/src/main/java/org/apache/commons/lang3/StringUtils.java">Apache Commons Lang</a>
     */
    public static String leftPad(final String str, final int size) {
        return leftPad(str, size, ' ');
    }

    /**
     * <p>
     * Left pad a String with a specified character.
     * </p>
     *
     * <p>
     * Pad to a size of {@code size}.
     * </p>
     *
     * <pre>
     * MoreStrings.leftPad(null, *, *)     = null
     * MoreStrings.leftPad("", 3, 'z')     = "zzz"
     * MoreStrings.leftPad("bat", 3, 'z')  = "bat"
     * MoreStrings.leftPad("bat", 5, 'z')  = "zzbat"
     * MoreStrings.leftPad("bat", 1, 'z')  = "bat"
     * MoreStrings.leftPad("bat", -1, 'z') = "bat"
     * </pre>
     *
     * <p>
     * Inspired by Apache Commons Lang StringUtils.
     *
     * @param str     the String to pad out, may be null
     * @param size    the size to pad to
     * @param padChar the character to pad with
     * @return left padded String or original String if no padding is necessary,
     * {@code null} if null String input
     * @see <a href="https://github.com/apache/commons-lang/blob/master/src/main/java/org/apache/commons/lang3/StringUtils.java">Apache Commons Lang</a>
     */
    public static String leftPad(final String str, final int size, final char padChar) {
        if (str == null) {
            return null;
        }
        final var pads = size - str.length();
        if (pads <= 0) {
            return str; // returns original String when possible
        }
        if (pads > PAD_LIMIT) {
            return leftPad(str, size, String.valueOf(padChar));
        }
        return repeat(padChar, pads).concat(str);
    }

    /**
     * <p>
     * Left pad a String with a specified String.
     * </p>
     *
     * <p>
     * Pad to a size of {@code size}.
     * </p>
     *
     * <pre>
     * MoreStrings.leftPad(null, *, *)      = null
     * MoreStrings.leftPad("", 3, "z")      = "zzz"
     * MoreStrings.leftPad("bat", 3, "yz")  = "bat"
     * MoreStrings.leftPad("bat", 5, "yz")  = "yzbat"
     * MoreStrings.leftPad("bat", 8, "yz")  = "yzyzybat"
     * MoreStrings.leftPad("bat", 1, "yz")  = "bat"
     * MoreStrings.leftPad("bat", -1, "yz") = "bat"
     * MoreStrings.leftPad("bat", 5, null)  = "  bat"
     * MoreStrings.leftPad("bat", 5, "")    = "  bat"
     * </pre>
     *
     * <p>
     * Inspired by Apache Commons Lang StringUtils.
     *
     * @param str    the String to pad out, may be null
     * @param size   the size to pad to
     * @param padStr the String to pad with, null or empty treated as single space
     * @return left padded String or original String if no padding is necessary,
     * {@code null} if null String input
     * @see <a href="https://github.com/apache/commons-lang/blob/master/src/main/java/org/apache/commons/lang3/StringUtils.java">Apache Commons Lang</a>
     */
    public static String leftPad(final String str, final int size, String padStr) {
        if (str == null) {
            return null;
        }
        if (isEmpty(padStr)) {
            padStr = SPACE;
        }
        final var padLen = padStr.length();
        final var strLen = str.length();
        final var pads = size - strLen;
        if (pads <= 0) {
            return str; // returns original String when possible
        }
        if (padLen == 1 && pads <= PAD_LIMIT) {
            return leftPad(str, size, padStr.charAt(0));
        }

        if (pads == padLen) {
            return padStr.concat(str);
        }
        if (pads < padLen) {
            return padStr.substring(0, pads).concat(str);
        }
        final var padding = new char[pads];
        final var padChars = padStr.toCharArray();
        for (var i = 0; i < pads; i++) {
            padding[i] = padChars[i % padLen];
        }
        return new String(padding).concat(str);
    }

    /**
     * <p>
     * Returns padding using the specified delimiter repeated to a given length.
     * </p>
     *
     * <pre>
     * MoreStrings.repeat('e', 0)  = ""
     * MoreStrings.repeat('e', 3)  = "eee"
     * MoreStrings.repeat('e', -2) = ""
     * </pre>
     *
     * <p>
     * Note: this method does not support padding with
     * <a href="http://www.unicode.org/glossary/#supplementary_character">Unicode
     * Supplementary Characters</a> as they require a pair of {@code char}s to be
     * represented. If you are needing to support full I18N of your applications
     * consider using <code>repeat(String, int)</code> instead.
     * </p>
     *
     * <p>
     * Inspired by Apache Commons Lang StringUtils.
     *
     * @param ch     character to repeat
     * @param repeat number of times to repeat char, negative treated as zero
     * @return String with repeated character
     * @see <a href="https://github.com/apache/commons-lang/blob/master/src/main/java/org/apache/commons/lang3/StringUtils.java">Apache Commons Lang</a>
     */
    public static String repeat(final char ch, final int repeat) {
        if (repeat <= 0) {
            return EMPTY;
        }
        final var buf = new char[repeat];
        for (var i = repeat - 1; i >= 0; i--) {
            buf[i] = ch;
        }
        return new String(buf);
    }

    /**
     * <p>
     * Strips any of a set of characters from the end of a String.
     * </p>
     *
     * <p>
     * A {@code null} input String returns {@code null}. An empty string ("") input
     * returns the empty string.
     * </p>
     *
     * <p>
     * If the stripChars String is {@code null}, whitespace is stripped as defined
     * by {@link Character#isWhitespace(char)}.
     * </p>
     *
     * <pre>
     * MoreStrings.stripEnd(null, *)          = null
     * MoreStrings.stripEnd("", *)            = ""
     * MoreStrings.stripEnd("abc", "")        = "abc"
     * MoreStrings.stripEnd("abc", null)      = "abc"
     * MoreStrings.stripEnd("  abc", null)    = "  abc"
     * MoreStrings.stripEnd("abc  ", null)    = "abc"
     * MoreStrings.stripEnd(" abc ", null)    = " abc"
     * MoreStrings.stripEnd("  abcyx", "xyz") = "  abc"
     * MoreStrings.stripEnd("120.00", ".0")   = "12"
     * </pre>
     *
     *
     * <p>
     * Inspired by Apache Commons Lang StringUtils.
     *
     * @param str        the String to remove characters from, may be null
     * @param stripChars the set of characters to remove, null treated as whitespace
     * @return the stripped String, {@code null} if null String input
     * @see <a href="https://github.com/apache/commons-lang/blob/master/src/main/java/org/apache/commons/lang3/StringUtils.java">Apache Commons Lang</a>
     */
    public static String stripEnd(final String str, final String stripChars) {
        int end;
        if (str == null || (end = str.length()) == 0) {
            return str;
        }

        if (stripChars == null) {
            while (end != 0 && Character.isWhitespace(str.charAt(end - 1))) {
                end--;
            }
        } else if (stripChars.isEmpty()) {
            return str;
        } else {
            while (end != 0 && stripChars.indexOf(str.charAt(end - 1)) != INDEX_NOT_FOUND) {
                end--;
            }
        }
        return str.substring(0, end);
    }

    /**
     * Returns the index within <code>seq</code> of the first occurrence of the
     * specified character. If a character with value <code>searchChar</code> occurs
     * in the character sequence represented by <code>seq</code>
     * <code>CharSequence</code> object, then the index (in Unicode code units) of
     * the first such occurrence is returned. For values of <code>searchChar</code>
     * in the range from 0 to 0xFFFF (inclusive), this is the smallest value
     * <i>k</i> such that: <blockquote>
     *
     * <pre>
     * this.charAt(<i>k</i>) == searchChar
     * </pre>
     *
     * </blockquote> is true. For other values of <code>searchChar</code>, it is the
     * smallest value <i>k</i> such that: <blockquote>
     *
     * <pre>
     * this.codePointAt(<i>k</i>) == searchChar
     * </pre>
     *
     * </blockquote> is true. In either case, if no such character occurs in
     * <code>seq</code>, then {@code INDEX_NOT_FOUND (-1)} is returned.
     *
     * <p>
     * Furthermore, a {@code null} or empty ("") CharSequence will return
     * {@code INDEX_NOT_FOUND (-1)}.
     * </p>
     *
     * <pre>
     * MoreStrings.indexOf(null, *)         = -1
     * MoreStrings.indexOf("", *)           = -1
     * MoreStrings.indexOf("aabaabaa", 'a') = 0
     * MoreStrings.indexOf("aabaabaa", 'b') = 2
     * </pre>
     *
     *
     * <p>
     * Inspired by Apache Commons Lang StringUtils.
     *
     * @param seq        the CharSequence to check, may be null
     * @param searchChar the character to find
     * @return the first index of the search character, -1 if no match or
     * {@code null} string input
     * @see <a href="https://github.com/apache/commons-lang/blob/master/src/main/java/org/apache/commons/lang3/StringUtils.java">Apache Commons Lang</a>
     */
    public static int indexOf(final CharSequence seq, final int searchChar) {
        if (isEmpty(seq)) {
            return INDEX_NOT_FOUND;
        }
        return indexOf(seq, searchChar, 0);
    }

    /**
     * Returns the index within <code>cs</code> of the first occurrence of the
     * specified character, starting the search at the specified index.
     * <p>
     * If a character with value <code>searchChar</code> occurs in the character
     * sequence represented by the <code>cs</code> object at an index no smaller
     * than <code>start</code>, then the index of the first such occurrence is
     * returned. For values of <code>searchChar</code> in the range from 0 to 0xFFFF
     * (inclusive), this is the smallest value <i>k</i> such that: <blockquote>
     *
     * <pre>
     * (this.charAt(<i>k</i>) == searchChar) &amp;&amp; (<i>k</i> &gt;= start)
     * </pre>
     *
     * </blockquote> is true. For other values of <code>searchChar</code>, it is the
     * smallest value <i>k</i> such that: <blockquote>
     *
     * <pre>
     * (this.codePointAt(<i>k</i>) == searchChar) &amp;&amp; (<i>k</i> &gt;= start)
     * </pre>
     *
     * </blockquote> is true. In either case, if no such character occurs inm
     * <code>cs</code> at or after position <code>start</code>, then <code>-1</code>
     * is returned.
     *
     * <p>
     * There is no restriction on the value of <code>start</code>. If it is
     * negative, it has the same effect as if it were zero: the entire
     * <code>CharSequence</code> may be searched. If it is greater than the length
     * of <code>cs</code>, it has the same effect as if it were equal to the length
     * of <code>cs</code>: <code>-1</code> is returned.
     *
     * <p>
     * All indices are specified in <code>char</code> values (Unicode code units).
     *
     * <p>
     * Inspired by Apache Commons Lang StringUtils.
     *
     * @param cs         the {@code CharSequence} to be processed, not null
     * @param searchChar the char to be searched for
     * @param start      the start index, negative starts at the string start
     * @return the index where the search char was found, -1 if not found
     * @see <a href="https://github.com/apache/commons-lang/blob/master/src/main/java/org/apache/commons/lang3/StringUtils.java">Apache Commons Lang</a>
     */
    @SuppressWarnings("squid:S3776") // owolff: original code
    public static int indexOf(final CharSequence cs, final int searchChar, int start) {
        if (isEmpty(cs)) {
            return INDEX_NOT_FOUND;
        }

        if (cs instanceof String string) {
            return string.indexOf(searchChar, start);
        }
        final var sz = cs.length();
        if (start < 0) {
            start = 0;
        }
        if (searchChar < Character.MIN_SUPPLEMENTARY_CODE_POINT) {
            for (var i = start; i < sz; i++) {
                if (cs.charAt(i) == searchChar) {
                    return i;
                }
            }
        }
        // supplementary characters (LANG1300)
        if (searchChar <= Character.MAX_CODE_POINT) {
            final var chars = Character.toChars(searchChar);
            for (var i = start; i < sz - 1; i++) {
                final var high = cs.charAt(i);
                final var low = cs.charAt(i + 1);
                if (high == chars[0] && low == chars[1]) {
                    return i;
                }
            }
        }
        return INDEX_NOT_FOUND;
    }

    /**
     * Used by the indexOf(CharSequence methods) as a green implementation of
     * indexOf.
     *
     * <p>
     * Inspired by Apache Commons Lang StringUtils.
     *
     * @param cs         the {@code CharSequence} to be processed
     * @param searchChar the {@code CharSequence} to be searched for
     * @param start      the start index
     * @return the index where the search sequence was found
     * @see <a href="https://github.com/apache/commons-lang/blob/master/src/main/java/org/apache/commons/lang3/StringUtils.java">Apache Commons Lang</a>
     */
    public static int indexOf(final CharSequence cs, final CharSequence searchChar, final int start) {
        if (cs == null || searchChar == null) {
            return INDEX_NOT_FOUND;
        }
        return cs.toString().indexOf(searchChar.toString(), start);
    }

    /**
     * Check whether the given {@code String} contains actual <em>text</em>.
     * <p>
     * More specifically, this method returns {@code true} if the {@code String} is
     * not {@code null}, its length is greater than 0, and it contains at least one
     * non-whitespace character.
     *
     * <p>
     * Inspired by Spring Framework StringUtils.
     *
     * @param str the {@code String} to check (maybe {@code null})
     * @return {@code true} if the {@code String} is not {@code null}, its length is
     * greater than 0, and it does not contain whitespace only
     * @see <a href="https://github.com/spring-projects/spring-framework/blob/main/spring-core/src/main/java/org/springframework/util/StringUtils.java">Spring Framework</a>
     */
    public static boolean hasNonWhitespaceChar(final CharSequence str) {
        if (isEmpty(str)) {
            return false;
        }

        final var strLen = str.length();
        for (var i = 0; i < strLen; i++) {
            if (!Character.isWhitespace(str.charAt(i))) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks a string for being non-null and not empty (checks without trimming)
     * Throws an {@link IllegalArgumentException} if String is null or empty
     *
     * @param underCheck to be checked
     * @return the given String
     */
    public static String requireNotEmpty(final String underCheck) {
        checkArgument(!isEmpty(underCheck), "Given String is Empty");
        return underCheck;
    }

    /**
     * Checks a string for being non-null and not empty (checks without trimming)
     * Throws an {@link IllegalArgumentException} if String is null or empty
     *
     * @param underCheck    to be checked
     * @param attributeName used for the creation of the error text
     * @return the given String
     */
    public static String requireNotEmpty(final String underCheck, final String attributeName) {
        checkArgument(!isEmpty(underCheck), "Attribute with name '" + attributeName + "' must not be empty");
        return underCheck;
    }

    /**
     * Checks a string for being non-null and not empty (checks with trimming)
     * Throws an {@link IllegalArgumentException} if String is null or empty
     *
     * @param underCheck to be checked
     * @return the given String
     */
    public static String requireNotEmptyTrimmed(final String underCheck) {
        checkArgument(!isBlank(underCheck), "Attribute must not be blank");
        return underCheck;
    }

    /**
     * Checks a string for being non-null and not empty (checks with trimming)
     * Throws an {@link IllegalArgumentException} if String is null or empty
     *
     * @param underCheck    to be checked
     * @param attributeName used for the creation of the error text
     * @return the given String
     */
    public static String requireNotEmptyTrimmed(final String underCheck, final String attributeName) {
        checkArgument(!isBlank(underCheck), "Attribute with name '" + attributeName + "' must not be blank");
        return underCheck;
    }

    /**
     * Returns the given string if it is non-null; the empty string otherwise.
     *
     * <p>
     * Inspired by Google Guava Strings.
     *
     * @param string the string to test and possibly return
     * @return {@code string} itself if it is non-null; {@code ""} if it is null
     * @see <a href="https://github.com/google/guava/blob/master/guava/src/com/google/common/base/Strings.java">Google Guava</a>
     */
    public static String nullToEmpty(String string) {
        if (null == string) {
            return "";
        }
        return string;
    }

    /**
     * Returns the given string if it is nonempty; {@code null} otherwise.
     *
     * <p>
     * Inspired by Google Guava Strings.
     *
     * @param string the string to test and possibly return
     * @return {@code string} itself if it is nonempty; {@code null} if it is empty
     * or null
     * @see <a href="https://github.com/google/guava/blob/master/guava/src/com/google/common/base/Strings.java">Google Guava</a>
     */
    public static String emptyToNull(String string) {
        if (null == string || string.isEmpty()) {
            return null;
        }
        return string;
    }

    /**
     * Null-safe trimming of a String value.
     *
     * @param string to be trimmed
     * @return <code>null</code> if the string is <code>null</code> otherwise the
     * trimmed string
     */
    public static String trimOrNull(final String string) {
        return null != string ? string.trim() : null;
    }

    /**
     * Returns the given {@code template} string with each occurrence of
     * {@code "%s"} replaced with the corresponding argument value from
     * {@code args}; or, if the placeholder and argument counts do not match,
     * returns a best-effort form of that string. Will not throw an exception under
     * normal conditions.
     *
     * <p>
     * <b>Note:</b> For most string-formatting needs, use {@link String#format
     * String.format}, {@link java.io.PrintWriter#format PrintWriter.format}, and
     * related methods. These support the full range of <a href=
     * "https://docs.oracle.com/javase/9/docs/api/java/util/Formatter.html#syntax">format
     * specifiers</a>, and alert you to usage errors by throwing
     * {@link java.util.IllegalFormatException}.
     *
     * <p>
     * In certain cases, such as outputting debugging information or constructing a
     * message to be used for another unchecked exception, an exception during
     * string formatting would serve little purpose except to supplant the real
     * information you were trying to provide. These are the cases this method is
     * made for; it instead generates a best-effort string with all supplied
     * argument values present. This method is also useful in environments such as
     * GWT where {@code String.format} is not available.
     *
     * <p>
     * <b>Warning:</b> Only the exact two-character placeholder sequence
     * {@code "%s"} is recognized.
     *
     * <p>
     * Inspired by Google Guava Strings.
     *
     * @param template a string containing zero or more {@code "%s"} placeholder
     *                 sequences. {@code
     *                 null}    is treated as the four-character string {@code "null"}.
     * @param args     the arguments to be substituted into the message template.
     *                 The first argument specified is substituted for the first
     *                 occurrence of {@code "%s"} in the template, and so forth. A
     *                 {@code null} argument is converted to the four-character
     *                 string {@code "null"}; non-null values are converted to
     *                 strings using {@link Object#toString()}.
     * @return the resulting formatting String
     * @see <a href="https://github.com/google/guava/blob/master/guava/src/com/google/common/base/Strings.java">Google Guava</a>
     */
    public static String lenientFormat(String template, Object... args) {
        template = String.valueOf(template); // null -> "null"

        final List<Object> lenientArgs;

        if (args == null) {
            lenientArgs = new ArrayList<>(1);
            lenientArgs.add("(Object[])null");
        } else {
            lenientArgs = new ArrayList<>(args.length);
            for (Object arg : args) {
                lenientArgs.add(lenientToString(arg));
            }
        }

        // start substituting the arguments into the '%s' placeholders
        StringBuilder builder = new StringBuilder(template.length() + 16 * lenientArgs.size());
        int templateStart = 0;
        int i = 0;
        while (i < lenientArgs.size()) {
            int placeholderStart = template.indexOf("%s", templateStart);
            if (placeholderStart == -1) {
                break;
            }
            builder.append(template, templateStart, placeholderStart);
            builder.append(lenientArgs.get(i++));
            templateStart = placeholderStart + 2;
        }
        builder.append(template, templateStart, template.length());

        // if we run out of placeholders, append the extra args in square braces
        if (i < lenientArgs.size()) {
            builder.append(" [");
            builder.append(lenientArgs.get(i++));
            while (i < lenientArgs.size()) {
                builder.append(", ");
                builder.append(lenientArgs.get(i++));
            }
            builder.append(']');
        }

        LOGGER.debug("No args given, returning template '%s'", template);
        return builder.toString();
    }

    /**
     * @param value  to be processed
     * @param suffix to be present
     * @return value with suffix
     */
    public static String ensureEndsWith(@NonNull final String value, @NonNull final String suffix) {
        if (!value.endsWith(suffix)) {
            return value + suffix;
        }
        return value;
    }

    /**
     * @see <a href="https://github.com/google/guava/blob/master/guava/src/com/google/common/base/Strings.java">Google Guava</a>
     */
    static String lenientToString(Object o) {
        try {
            if (o != null && o.getClass().isArray()) {
                if (o instanceof Object[] arr) {
                    return Arrays.toString(arr);
                } else if (o instanceof int[] arr) {
                    return Arrays.toString(arr);
                } else if (o instanceof long[] arr) {
                    return Arrays.toString(arr);
                } else if (o instanceof double[] arr) {
                    return Arrays.toString(arr);
                } else if (o instanceof float[] arr) {
                    return Arrays.toString(arr);
                } else if (o instanceof boolean[] arr) {
                    return Arrays.toString(arr);
                } else if (o instanceof byte[] arr) {
                    return Arrays.toString(arr);
                } else if (o instanceof short[] arr) {
                    return Arrays.toString(arr);
                } else if (o instanceof char[] arr) {
                    return Arrays.toString(arr);
                }
            }
            return String.valueOf(o);
        } catch (Exception e) {
            // Default toString() behavior - see Object.toString()
            var objectToString = (o == null) ? "null" :
                    o.getClass().getName() + '@' + Integer.toHexString(System.identityHashCode(o));
            LOGGER.warn(e, "Exception during lenientFormat for {}", objectToString);
            return "<" + objectToString + " threw " + e.getClass().getName() + ">";
        }
    }

    /**
     * @param checker the predicate to check each given value against. it decides if
     *                a value qualifies to be returned.
     * @param values  to be evaluated
     * @return first string that is accepted by the given {@link Predicate} or
     * {@link Optional#empty()}
     */
    public static Optional<String> coalesce(Predicate<String> checker, String... values) {
        if (null != values) {
            for (String value : values) {
                if (!checker.test(value)) {
                    return Optional.of(value);
                }
            }
        }
        return Optional.empty();
    }

    /**
     * @param values to be evaluated
     * @return first string that is not {@link #isEmpty(CharSequence)}
     */
    public static Optional<String> firstNonEmpty(String... values) {
        return coalesce(MoreStrings::isEmpty, values);
    }

    /**
     * @param values to be evaluated
     * @return first string that is not {@link #isBlank(CharSequence)}
     */
    public static Optional<String> firstNonBlank(String... values) {
        return coalesce(MoreStrings::isBlank, values);
    }
}
