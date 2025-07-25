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
package de.cuioss.tools.io;

import lombok.experimental.UtilityClass;

import java.io.File;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Deque;

/**
 * Copied from commons.io:org.apache.commons.io.FilenameUtils
 * <p>
 * General filename and filepath manipulation utilities.
 * <p>
 * When dealing with filenames you can hit problems when moving from a Windows
 * based development machine to a Unix based production machine. This class aims
 * to help avoid those problems.
 * <p>
 * <b>NOTE</b>: You may be able to avoid using this class entirely simply by
 * using JDK {@link java.io.File File} objects and the two argument constructor
 * {@link java.io.File#File(java.io.File, java.lang.String) File(File,String)}.
 * <p>
 * Most methods on this class are designed to work the same on both Unix and
 * Windows. Those that don't include 'System', 'Unix' or 'Windows' in their
 * name.
 * <p>
 * Most methods recognise both separators (forward and back), and both sets of
 * prefixes. See the javadoc of each method for details.
 * <p>
 * This class defines six components within a filename (example
 * C:\dev\project\file.txt):
 * <ul>
 * <li>the prefix - C:\</li>
 * <li>the path - dev\project\</li>
 * <li>the full path - C:\dev\project\</li>
 * <li>the name - file.txt</li>
 * <li>the base name - file</li>
 * <li>the extension - txt</li>
 * </ul>
 * Note that this class works best if directory filenames end with a separator.
 * If you omit the last separator, it is impossible to determine if the filename
 * corresponds to a file or a directory. As a result, we have chosen to say it
 * corresponds to a file.
 * <p>
 * This class only supports Unix and Windows style names. Prefixes are matched
 * as follows:
 *
 * <pre>
 * Windows:
 * a\b\c.txt           --&gt; ""          --&gt; relative
 * \a\b\c.txt          --&gt; "\"         --&gt; current drive absolute
 * C:a\b\c.txt         --&gt; "C:"        --&gt; drive relative
 * C:\a\b\c.txt        --&gt; "C:\"       --&gt; absolute
 * \\server\a\b\c.txt  --&gt; "\\server\" --&gt; UNC
 *
 * Unix:
 * a/b/c.txt           --&gt; ""          --&gt; relative
 * /a/b/c.txt          --&gt; "/"         --&gt; absolute
 * ~/a/b/c.txt         --&gt; "~/"        --&gt; current user
 * ~                   --&gt; "~/"        --&gt; current user (slash added)
 * ~user/a/b/c.txt     --&gt; "~user/"    --&gt; named user
 * ~user               --&gt; "~user/"    --&gt; named user (slash added)
 * </pre>
 *
 * Both prefix styles are matched always, irrespective of the machine that you
 * are currently running on.
 * <p>
 * Origin of code: Excalibur, Alexandria, Tomcat, Commons-Utils.
 * </p>
 *
 */
@SuppressWarnings("javaarchitecture:S7027")
// Intended circular dependency with IOCase
@UtilityClass
public class FilenameUtils {

    private static final int NOT_FOUND = -1;

    /**
     * The extension separator character.
     *
     */
    public static final char EXTENSION_SEPARATOR = '.';

    /**
     * The Unix separator character.
     */
    private static final char UNIX_SEPARATOR = '/';

    /**
     * The Windows separator character.
     */
    private static final char WINDOWS_SEPARATOR = '\\';

    /**
     * The system separator character.
     */
    private static final char SYSTEM_SEPARATOR = File.separatorChar;

    /**
     * The separator character that is the opposite of the system separator.
     */
    private static final char OTHER_SEPARATOR;

    static {
        if (isSystemWindows()) {
            OTHER_SEPARATOR = UNIX_SEPARATOR;
        } else {
            OTHER_SEPARATOR = WINDOWS_SEPARATOR;
        }
    }

    // -----------------------------------------------------------------------
    /**
     * Determines if Windows file system is in use.
     *
     * @return true if the system is Windows
     */
    static boolean isSystemWindows() {
        return SYSTEM_SEPARATOR == WINDOWS_SEPARATOR;
    }

    // -----------------------------------------------------------------------
    /**
     * Checks if the character is a separator.
     *
     * @param ch the character to check
     * @return true if it is a separator character
     */
    private static boolean isSeparator(final char ch) {
        return ch == UNIX_SEPARATOR || ch == WINDOWS_SEPARATOR;
    }

    // -----------------------------------------------------------------------
    /**
     * Normalizes a path, removing double and single dot path steps.
     * <p>
     * This method normalizes a path to a standard format. The input may contain
     * separators in either Unix or Windows format. The output will contain
     * separators in the format of the system.
     * <p>
     * A trailing slash will be retained. A double slash will be merged to a single
     * slash (but UNC names are handled). A single dot path segment will be removed.
     * A double dot will cause that path segment and the one before to be removed.
     * If the double dot has no parent path segment to work with, {@code null} is
     * returned.
     * <p>
     * The output will be the same on both Unix and Windows except for the separator
     * character.
     *
     * <pre>
     * /foo//               --&gt;   /foo/
     * /foo/./              --&gt;   /foo/
     * /foo/../bar          --&gt;   /bar
     * /foo/../bar/         --&gt;   /bar/
     * /foo/../bar/../baz   --&gt;   /baz
     * //foo//./bar         --&gt;   /foo/bar
     * /../                 --&gt;   null
     * ../foo               --&gt;   null
     * foo/bar/..           --&gt;   foo/
     * foo/../../bar        --&gt;   null
     * foo/../bar           --&gt;   bar
     * //server/foo/../bar  --&gt;   //server/bar
     * //server/../bar      --&gt;   null
     * C:\foo\..\bar        --&gt;   C:\bar
     * C:\..\bar            --&gt;   null
     * ~/foo/../bar/        --&gt;   ~/bar/
     * ~/../bar             --&gt;   null
     * </pre>
     *
     * (Note the file separator returned will be correct for Windows/Unix)
     *
     * @param filename the filename to normalize, null returns null
     * @return the normalized filename, or null if invalid. Null bytes inside string
     *         will be removed
     */
    public static String normalize(final String filename) {
        return doNormalize(filename, SYSTEM_SEPARATOR, true);
    }

    /**
     * Normalizes a path, removing double and single dot path steps.
     * <p>
     * This method normalizes a path to a standard format. The input may contain
     * separators in either Unix or Windows format. The output will contain
     * separators in the format specified.
     * <p>
     * A trailing slash will be retained. A double slash will be merged to a single
     * slash (but UNC names are handled). A single dot path segment will be removed.
     * A double dot will cause that path segment and the one before to be removed.
     * If the double dot has no parent path segment to work with, {@code null} is
     * returned.
     * <p>
     * The output will be the same on both Unix and Windows including the separator
     * character.
     *
     * <pre>
     * /foo//               --&gt;   /foo/
     * /foo/./              --&gt;   /foo/
     * /foo/../bar          --&gt;   /bar
     * /foo/../bar/         --&gt;   /bar/
     * /foo/../bar/../baz   --&gt;   /baz
     * //foo//./bar         --&gt;   /foo/bar
     * /../                 --&gt;   null
     * ../foo               --&gt;   null
     * foo/bar/..           --&gt;   foo/
     * foo/../../bar        --&gt;   null
     * foo/../bar           --&gt;   bar
     * //server/foo/../bar  --&gt;   //server/bar
     * //server/../bar      --&gt;   null
     * C:\foo\..\bar        --&gt;   C:\bar
     * C:\..\bar            --&gt;   null
     * ~/foo/../bar/        --&gt;   ~/bar/
     * ~/../bar             --&gt;   null
     * </pre>
     *
     * The output will be the same on both Unix and Windows including the separator
     * character.
     *
     * @param filename      the filename to normalize, null returns null
     * @param unixSeparator {@code true} if a unix separator should be used or
     *                      {@code false} if a windows separator should be used.
     * @return the normalized filename, or null if invalid. Null bytes inside string
     *         will be removed
     */
    public static String normalize(final String filename, final boolean unixSeparator) {
        final var separator = unixSeparator ? UNIX_SEPARATOR : WINDOWS_SEPARATOR;
        return doNormalize(filename, separator, true);
    }

    // -----------------------------------------------------------------------
    /**
     * Normalizes a path, removing double and single dot path steps, and removing
     * any final directory separator.
     * <p>
     * This method normalizes a path to a standard format. The input may contain
     * separators in either Unix or Windows format. The output will contain
     * separators in the format of the system.
     * <p>
     * A trailing slash will be removed. A double slash will be merged to a single
     * slash (but UNC names are handled). A single dot path segment will be removed.
     * A double dot will cause that path segment and the one before to be removed.
     * If the double dot has no parent path segment to work with, {@code null} is
     * returned.
     * <p>
     * The output will be the same on both Unix and Windows except for the separator
     * character.
     *
     * <pre>
     * /foo//               --&gt;   /foo
     * /foo/./              --&gt;   /foo
     * /foo/../bar          --&gt;   /bar
     * /foo/../bar/         --&gt;   /bar
     * /foo/../bar/../baz   --&gt;   /baz
     * //foo//./bar         --&gt;   /foo/bar
     * /../                 --&gt;   null
     * ../foo               --&gt;   null
     * foo/bar/..           --&gt;   foo
     * foo/../../bar        --&gt;   null
     * foo/../bar           --&gt;   bar
     * //server/foo/../bar  --&gt;   //server/bar
     * //server/../bar      --&gt;   null
     * C:\foo\..\bar        --&gt;   C:\bar
     * C:\..\bar            --&gt;   null
     * ~/foo/../bar/        --&gt;   ~/bar
     * ~/../bar             --&gt;   null
     * </pre>
     *
     * (Note the file separator returned will be correct for Windows/Unix)
     *
     * @param filename the filename to normalize, null returns null
     * @return the normalized filename, or null if invalid. Null bytes inside string
     *         will be removed
     */
    public static String normalizeNoEndSeparator(final String filename) {
        return doNormalize(filename, SYSTEM_SEPARATOR, false);
    }

    /**
     * Normalizes a path, removing double and single dot path steps, and removing
     * any final directory separator.
     * <p>
     * This method normalizes a path to a standard format. The input may contain
     * separators in either Unix or Windows format. The output will contain
     * separators in the format specified.
     * <p>
     * A trailing slash will be removed. A double slash will be merged to a single
     * slash (but UNC names are handled). A single dot path segment will be removed.
     * A double dot will cause that path segment and the one before to be removed.
     * If the double dot has no parent path segment to work with, {@code null} is
     * returned.
     * <p>
     * The output will be the same on both Unix and Windows including the separator
     * character.
     *
     * <pre>
     * /foo//               --&gt;   /foo
     * /foo/./              --&gt;   /foo
     * /foo/../bar          --&gt;   /bar
     * /foo/../bar/         --&gt;   /bar
     * /foo/../bar/../baz   --&gt;   /baz
     * //foo//./bar         --&gt;   /foo/bar
     * /../                 --&gt;   null
     * ../foo               --&gt;   null
     * foo/bar/..           --&gt;   foo
     * foo/../../bar        --&gt;   null
     * foo/../bar           --&gt;   bar
     * //server/foo/../bar  --&gt;   //server/bar
     * //server/../bar      --&gt;   null
     * C:\foo\..\bar        --&gt;   C:\bar
     * C:\..\bar            --&gt;   null
     * ~/foo/../bar/        --&gt;   ~/bar
     * ~/../bar             --&gt;   null
     * </pre>
     *
     * @param filename      the filename to normalize, null returns null
     * @param unixSeparator {@code true} if a unix separator should be used or
     *                      {@code false} if a windows separator should be used.
     * @return the normalized filename, or null if invalid. Null bytes inside string
     *         will be removed
     */
    public static String normalizeNoEndSeparator(final String filename, final boolean unixSeparator) {
        final var separator = unixSeparator ? UNIX_SEPARATOR : WINDOWS_SEPARATOR;
        return doNormalize(filename, separator, false);
    }

    /**
     * Internal method to perform the normalization.
     *
     * @param filename      the filename
     * @param separator     The separator character to use
     * @param keepSeparator true to keep the final separator
     * @return the normalized filename. Null bytes inside string will be removed.
     */
    private static String doNormalize(final String filename, final char separator, final boolean keepSeparator) {
        if (filename == null) {
            return null;
        }

        failIfNullBytePresent(filename);

        var size = filename.length();
        if (size == 0) {
            return filename;
        }
        final var prefix = getPrefixLength(filename);
        if (prefix < 0) {
            return null;
        }

        final var array = new char[size + 2]; // +1 for possible extra slash, +2 for arraycopy
        filename.getChars(0, filename.length(), array, 0);

        // Normalize path components
        var context = new NormalizationContext(array, size, prefix, separator);
        fixSeparators(context);
        context.lastIsDirectory = addTrailingSeparatorIfNeeded(context);
        context.size = removeAdjoiningSlashes(context);
        removeDotSlashes(context);
        removeDoubleDotSlashes(context);

        return buildNormalizedPath(context, keepSeparator);
    }

    private static class NormalizationContext {
        final char[] array;
        int size;
        final int prefix;
        final char separator;
        boolean lastIsDirectory;

        NormalizationContext(char[] array, int size, int prefix, char separator) {
            this.array = array;
            this.size = size;
            this.prefix = prefix;
            this.separator = separator;
            this.lastIsDirectory = true;
        }
    }

    private static void fixSeparators(NormalizationContext context) {
        final var otherSeparator = context.separator == SYSTEM_SEPARATOR ? OTHER_SEPARATOR : SYSTEM_SEPARATOR;
        for (var i = 0; i < context.array.length; i++) {
            if (context.array[i] == otherSeparator) {
                context.array[i] = context.separator;
            }
        }
    }

    private static boolean addTrailingSeparatorIfNeeded(NormalizationContext context) {
        if (context.array[context.size - 1] != context.separator) {
            context.array[context.size] = context.separator;
            context.size++;
            return false;
        }
        return true;
    }

    private static int removeAdjoiningSlashes(NormalizationContext context) {
        var size = context.size;
        var i = context.prefix + 1;
        while (i < size) {
            if (context.array[i] == context.separator && context.array[i - 1] == context.separator) {
                System.arraycopy(context.array, i, context.array, i - 1, size - i);
                size--;
                // Don't increment i to recheck this position
            } else {
                i++;
            }
        }
        return size;
    }

    private static void removeDotSlashes(NormalizationContext context) {
        var size = context.size;
        var i = context.prefix + 1;
        while (i < size) {
            if (context.array[i] == context.separator && context.array[i - 1] == '.'
                    && (i == context.prefix + 1 || context.array[i - 2] == context.separator)) {
                if (i == size - 1) {
                    context.lastIsDirectory = true;
                }
                System.arraycopy(context.array, i + 1, context.array, i - 1, size - i);
                size -= 2;
                // Don't increment i to recheck this position
            } else {
                i++;
            }
        }
        context.size = size;
    }

    @SuppressWarnings("squid:ForLoopCounterChangedCheck") // loop counter modification needed for algorithm
    private static void removeDoubleDotSlashes(NormalizationContext context) {
        var size = context.size;
        for (var i = context.prefix + 2; i < size; i++) {
            if (isDoubleDotPattern(context, i)) {
                if (i == context.prefix + 2) {
                    context.size = -1; // Signal invalid path
                    return;
                }

                if (i == size - 1) {
                    context.lastIsDirectory = true;
                }

                var result = findAndRemoveParentDirectory(context, i, size);
                if (result != null) {
                    size = result.newSize;
                    i = result.newPosition - 1; // Will be incremented by loop
                } else {
                    // remove a/../ from a/../c
                    System.arraycopy(context.array, i + 1, context.array, context.prefix, size - i);
                    size -= i + 1 - context.prefix;
                    i = context.prefix;
                }
            }
        }
        context.size = size;
    }

    private static boolean isDoubleDotPattern(NormalizationContext context, int i) {
        return context.array[i] == context.separator
                && context.array[i - 1] == '.'
                && context.array[i - 2] == '.'
                && (i == context.prefix + 2 || context.array[i - 3] == context.separator);
    }

    private static RemovalResult findAndRemoveParentDirectory(NormalizationContext context, int i, int size) {
        for (var j = i - 4; j >= context.prefix; j--) {
            if (context.array[j] == context.separator) {
                // remove b/../ from a/b/../c
                System.arraycopy(context.array, i + 1, context.array, j + 1, size - i);
                return new RemovalResult(size - (i - j), j + 1);
            }
        }
        return null;
    }

    private record RemovalResult(int newSize, int newPosition) {
    }

    private static String buildNormalizedPath(NormalizationContext context, boolean keepSeparator) {
        if (context.size < 0) {
            return null; // Invalid path from double-dot processing
        }
        if (context.size == 0) { // should never be less than 0
            return "";
        }
        if (context.size <= context.prefix || context.lastIsDirectory && keepSeparator) {
            return new String(context.array, 0, context.size); // keep trailing separator
        }
        return new String(context.array, 0, context.size - 1); // lose trailing separator
    }

    // -----------------------------------------------------------------------
    /**
     * Concatenates a filename to a base path using normal command line style rules.
     * <p>
     * The effect is equivalent to resultant directory after changing directory to
     * the first argument, followed by changing directory to the second argument.
     * <p>
     * The first argument is the base path, the second is the path to concatenate.
     * The returned path is always normalized via {@link #normalize(String)}, thus
     * <code>..</code> is handled.
     * <p>
     * If <code>pathToAdd</code> is absolute (has an absolute prefix), then it will
     * be normalized and returned. Otherwise, the paths will be joined, normalized
     * and returned.
     * <p>
     * The output will be the same on both Unix and Windows except for the separator
     * character.
     *
     * <pre>
     * /foo/ + bar          --&gt;   /foo/bar
     * /foo + bar           --&gt;   /foo/bar
     * /foo + /bar          --&gt;   /bar
     * /foo + C:/bar        --&gt;   C:/bar
     * /foo + C:bar         --&gt;   C:bar (*)
     * /foo/a/ + ../bar     --&gt;   foo/bar
     * /foo/ + ../../bar    --&gt;   null
     * /foo/ + /bar         --&gt;   /bar
     * /foo/.. + /bar       --&gt;   /bar
     * /foo + bar/c.txt     --&gt;   /foo/bar/c.txt
     * /foo/c.txt + bar     --&gt;   /foo/c.txt/bar (!)
     * </pre>
     *
     * (*) Note that the Windows relative drive prefix is unreliable when used with
     * this method. (!) Note that the first parameter must be a path. If it ends
     * with a name, then the name will be built into the concatenated path. If this
     * might be a problem, use {@link #getFullPath(String)} on the base path
     * argument.
     *
     * @param basePath          the base path to attach to, always treated as a path
     * @param fullFilenameToAdd the filename (or path) to attach to the base
     * @return the concatenated path, or null if invalid. Null bytes inside string
     *         will be removed
     */
    public static String concat(final String basePath, final String fullFilenameToAdd) {
        final var prefix = getPrefixLength(fullFilenameToAdd);
        if (prefix < 0) {
            return null;
        }
        if (prefix > 0) {
            return normalize(fullFilenameToAdd);
        }
        if (basePath == null) {
            return null;
        }
        final var len = basePath.length();
        if (len == 0) {
            return normalize(fullFilenameToAdd);
        }
        final var ch = basePath.charAt(len - 1);
        if (isSeparator(ch)) {
            return normalize(basePath + fullFilenameToAdd);
        }
        return normalize(basePath + '/' + fullFilenameToAdd);
    }

    /**
     * Determines whether the {@code parent} directory contains the {@code child}
     * element (a file or directory).
     * <p>
     * The files names are expected to be normalized.
     * </p>
     *
     * Edge cases:
     * <ul>
     * <li>A {@code directory} must not be null: if null, throw
     * IllegalArgumentException</li>
     * <li>A directory does not contain itself: return false</li>
     * <li>A null child file is not contained in any parent: return false</li>
     * </ul>
     *
     * @param canonicalParent the file to consider as the parent.
     * @param canonicalChild  the file to consider as the child.
     * @return true is the candidate leaf is under by the specified composite. False
     *         otherwise.
     */
    public static boolean directoryContains(final String canonicalParent, final String canonicalChild) {

        // Fail fast against NullPointerException
        if (canonicalParent == null) {
            throw new IllegalArgumentException("Directory must not be null");
        }

        if (canonicalChild == null) {
            return false;
        }

        // Normalize paths to handle trailing separators consistently
        final String normalizedParent = normalizeNoEndSeparator(canonicalParent);
        final String normalizedChild = normalizeNoEndSeparator(canonicalChild);

        // A directory does not contain itself
        if (normalizedParent == null || normalizedChild == null ||
                IOCase.SYSTEM.checkEquals(normalizedParent, normalizedChild)) {
            return false;
        }

        // Check if child path starts with parent path followed by a separator
        // Special case: if parent is root directory, don't add extra separator
        if ("/".equals(normalizedParent) || "\\".equals(normalizedParent) ||
                (normalizedParent.length() >= 2 && normalizedParent.charAt(1) == ':' &&
                        (normalizedParent.endsWith("/") || normalizedParent.endsWith("\\")))) {
            return IOCase.SYSTEM.checkStartsWith(normalizedChild, normalizedParent) &&
                    !IOCase.SYSTEM.checkEquals(normalizedParent, normalizedChild);
        }

        return IOCase.SYSTEM.checkStartsWith(normalizedChild, normalizedParent + SYSTEM_SEPARATOR);
    }

    // -----------------------------------------------------------------------
    /**
     * Converts all separators to the Unix separator of forward slash.
     *
     * @param path the path to be changed, null ignored
     * @return the updated path
     */
    public static String separatorsToUnix(final String path) {
        if (path == null || path.indexOf(WINDOWS_SEPARATOR) == NOT_FOUND) {
            return path;
        }
        return path.replace(WINDOWS_SEPARATOR, UNIX_SEPARATOR);
    }

    /**
     * Converts all separators to the Windows separator of backslash.
     *
     * @param path the path to be changed, null ignored
     * @return the updated path
     */
    public static String separatorsToWindows(final String path) {
        if (path == null || path.indexOf(UNIX_SEPARATOR) == NOT_FOUND) {
            return path;
        }
        return path.replace(UNIX_SEPARATOR, WINDOWS_SEPARATOR);
    }

    /**
     * Converts all separators to the system separator.
     *
     * @param path the path to be changed, null ignored
     * @return the updated path
     */
    public static String separatorsToSystem(final String path) {
        if (path == null) {
            return null;
        }
        if (isSystemWindows()) {
            return separatorsToWindows(path);
        }
        return separatorsToUnix(path);
    }

    // -----------------------------------------------------------------------
    /**
     * Returns the length of the filename prefix, such as <code>C:/</code> or
     * <code>~/</code>.
     * <p>
     * This method will handle a file in either Unix or Windows format. The prefix
     * length includes the first slash in the full filename if
     * applicable. Thus, it is possible that the length returned is greater than the
     * length of the input string.
     *
     * <pre>
     * Windows:
     * a\b\c.txt           --&gt; ""          --&gt; relative
     * \a\b\c.txt          --&gt; "\"         --&gt; current drive absolute
     * C:a\b\c.txt         --&gt; "C:"        --&gt; drive relative
     * C:\a\b\c.txt        --&gt; "C:\"       --&gt; absolute
     * \\server\a\b\c.txt  --&gt; "\\server\" --&gt; UNC
     * \\\a\b\c.txt        --&gt;  error, length = -1
     *
     * Unix:
     * a/b/c.txt           --&gt; ""          --&gt; relative
     * /a/b/c.txt          --&gt; "/"         --&gt; absolute
     * ~/a/b/c.txt         --&gt; "~/"        --&gt; current user
     * ~                   --&gt; "~/"        --&gt; current user (slash added)
     * ~user/a/b/c.txt     --&gt; "~user/"    --&gt; named user
     * ~user               --&gt; "~user/"    --&gt; named user (slash added)
     * //server/a/b/c.txt  --&gt; "//server/"
     * ///a/b/c.txt        --&gt; error, length = -1
     * </pre>
     * <p>
     * The output will be the same irrespective of the machine that the code is
     * running on. i.e. both Unix and Windows prefixes are matched regardless.
     *
     * @param filename the filename to find the prefix in, null returns -1
     * @return the length of the prefix, -1 if invalid or null
     */
    @SuppressWarnings({"squid:S3776"}) // owolff: original code
    public static int getPrefixLength(final String filename) {
        if (filename == null) {
            return NOT_FOUND;
        }
        final var len = filename.length();
        if (len == 0) {
            return 0;
        }
        var ch0 = filename.charAt(0);
        if (ch0 == ':') {
            return NOT_FOUND;
        }
        if (len == 1) {
            if (ch0 == '~') {
                return 2; // return a length greater than the input
            }
            return isSeparator(ch0) ? 1 : 0;
        }
        if (ch0 == '~') {
            var posUnix = filename.indexOf(UNIX_SEPARATOR, 1);
            var posWin = filename.indexOf(WINDOWS_SEPARATOR, 1);
            if (posUnix == NOT_FOUND && posWin == NOT_FOUND) {
                return len + 1; // return a length greater than the input
            }
            posUnix = posUnix == NOT_FOUND ? posWin : posUnix;
            posWin = posWin == NOT_FOUND ? posUnix : posWin;
            return Math.min(posUnix, posWin) + 1;
        }
        final var ch1 = filename.charAt(1);
        if (ch1 == ':') {
            ch0 = Character.toUpperCase(ch0);
            if (ch0 >= 'A' && ch0 <= 'Z') {
                if (len == 2 || !isSeparator(filename.charAt(2))) {
                    return 2;
                }
                return 3;
            }
            if (ch0 == UNIX_SEPARATOR) {
                return 1;
            }
            return NOT_FOUND;

        }
        if (!isSeparator(ch0) || !isSeparator(ch1)) {
            return isSeparator(ch0) ? 1 : 0;
        }
        var posUnix = filename.indexOf(UNIX_SEPARATOR, 2);
        var posWin = filename.indexOf(WINDOWS_SEPARATOR, 2);
        if (posUnix == NOT_FOUND && posWin == NOT_FOUND || posUnix == 2 || posWin == 2) {
            return NOT_FOUND;
        }
        posUnix = posUnix == NOT_FOUND ? posWin : posUnix;
        posWin = posWin == NOT_FOUND ? posUnix : posWin;
        return Math.min(posUnix, posWin) + 1;
    }

    /**
     * Returns the index of the last directory separator character.
     * <p>
     * This method will handle a file in either Unix or Windows format. The position
     * of the last forward or backslash is returned.
     * <p>
     * The output will be the same irrespective of the machine that the code is
     * running on.
     *
     * @param filename the filename to find the last path separator in, null returns
     *                 -1
     * @return the index of the last separator character, or -1 if there is no such
     *         character
     */
    public static int indexOfLastSeparator(final String filename) {
        if (filename == null) {
            return NOT_FOUND;
        }
        final var lastUnixPos = filename.lastIndexOf(UNIX_SEPARATOR);
        final var lastWindowsPos = filename.lastIndexOf(WINDOWS_SEPARATOR);
        return Math.max(lastUnixPos, lastWindowsPos);
    }

    /**
     * Returns the index of the last extension separator character, which is a dot.
     * <p>
     * This method also checks that there is no directory separator after the last
     * dot. To do this it uses {@link #indexOfLastSeparator(String)} which will
     * handle a file in either Unix or Windows format.
     * </p>
     * <p>
     * The output will be the same irrespective of the machine that the code is
     * running on.
     * </p>
     *
     * @param filename the filename to find the last extension separator in, null
     *                 returns -1
     * @return the index of the last extension separator character, or -1 if there
     *         is no such character
     */
    public static int indexOfExtension(final String filename) {
        if (filename == null) {
            return NOT_FOUND;
        }
        final var extensionPos = filename.lastIndexOf(EXTENSION_SEPARATOR);
        final var lastSeparator = indexOfLastSeparator(filename);
        return lastSeparator > extensionPos ? NOT_FOUND : extensionPos;
    }

    // -----------------------------------------------------------------------
    /**
     * Gets the prefix from a full filename, such as <code>C:/</code> or
     * <code>~/</code>.
     * <p>
     * This method will handle a file in either Unix or Windows format. The prefix
     * includes the first slash in the full filename where applicable.
     *
     * <pre>
     * Windows:
     * a\b\c.txt           --&gt; ""          --&gt; relative
     * \a\b\c.txt          --&gt; "\"         --&gt; current drive absolute
     * C:a\b\c.txt         --&gt; "C:"        --&gt; drive relative
     * C:\a\b\c.txt        --&gt; "C:\"       --&gt; absolute
     * \\server\a\b\c.txt  --&gt; "\\server\" --&gt; UNC
     *
     * Unix:
     * a/b/c.txt           --&gt; ""          --&gt; relative
     * /a/b/c.txt          --&gt; "/"         --&gt; absolute
     * ~/a/b/c.txt         --&gt; "~/"        --&gt; current user
     * ~                   --&gt; "~/"        --&gt; current user (slash added)
     * ~user/a/b/c.txt     --&gt; "~user/"    --&gt; named user
     * ~user               --&gt; "~user/"    --&gt; named user (slash added)
     * </pre>
     * <p>
     * The output will be the same irrespective of the machine that the code is
     * running on. i.e. both Unix and Windows prefixes are matched regardless.
     *
     * @param filename the filename to query, null returns null
     * @return the prefix of the file, null if invalid. Null bytes inside string
     *         will be removed
     */
    public static String getPrefix(final String filename) {
        if (filename == null) {
            return null;
        }
        final var len = getPrefixLength(filename);
        if (len < 0) {
            return null;
        }
        if (len > filename.length()) {
            failIfNullBytePresent(filename + UNIX_SEPARATOR);
            return filename + UNIX_SEPARATOR;
        }
        final var path = filename.substring(0, len);
        failIfNullBytePresent(path);
        return path;
    }

    /**
     * Gets the path from a full filename, which excludes the prefix.
     * <p>
     * This method will handle a file in either Unix or Windows format. The method
     * is entirely text based, and returns the text before and including the last
     * forward or backslash.
     *
     * <pre>
     * C:\a\b\c.txt --&gt; a\b\
     * ~/a/b/c.txt  --&gt; a/b/
     * a.txt        --&gt; ""
     * a/b/c        --&gt; a/b/
     * a/b/c/       --&gt; a/b/c/
     * </pre>
     * <p>
     * The output will be the same irrespective of the machine that the code is
     * running on.
     * <p>
     * This method drops the prefix from the result. See
     * {@link #getFullPath(String)} for the method that retains the prefix.
     *
     * @param filename the filename to query, null returns null
     * @return the path of the file, an empty string if none exists, null if
     *         invalid. Null bytes inside string will be removed
     */
    public static String getPath(final String filename) {
        return doGetPath(filename, 1);
    }

    /**
     * Gets the path from a full filename, which excludes the prefix, and also
     * excluding the final directory separator.
     * <p>
     * This method will handle a file in either Unix or Windows format. The method
     * is entirely text based, and returns the text before the last forward or
     * backslash.
     *
     * <pre>
     * C:\a\b\c.txt --&gt; a\b
     * ~/a/b/c.txt  --&gt; a/b
     * a.txt        --&gt; ""
     * a/b/c        --&gt; a/b
     * a/b/c/       --&gt; a/b/c
     * </pre>
     * <p>
     * The output will be the same irrespective of the machine that the code is
     * running on.
     * <p>
     * This method drops the prefix from the result. See
     * {@link #getFullPathNoEndSeparator(String)} for the method that retains the
     * prefix.
     *
     * @param filename the filename to query, null returns null
     * @return the path of the file, an empty string if none exists, null if
     *         invalid. Null bytes inside string will be removed
     */
    public static String getPathNoEndSeparator(final String filename) {
        return doGetPath(filename, 0);
    }

    /**
     * Does the work of getting the path.
     *
     * @param filename     the filename
     * @param separatorAdd 0 to omit the end separator, 1 to return it
     * @return the path. Null bytes inside string will be removed
     */
    private static String doGetPath(final String filename, final int separatorAdd) {
        if (filename == null) {
            return null;
        }
        final var prefix = getPrefixLength(filename);
        if (prefix < 0) {
            return null;
        }
        final var index = indexOfLastSeparator(filename);
        final var endIndex = index + separatorAdd;
        if (prefix >= filename.length() || index < 0 || prefix >= endIndex) {
            return "";
        }
        final var path = filename.substring(prefix, endIndex);
        failIfNullBytePresent(path);
        return path;
    }

    /**
     * Gets the full path from a full filename, which is the prefix + path.
     * <p>
     * This method will handle a file in either Unix or Windows format. The method
     * is entirely text based, and returns the text before and including the last
     * forward or backslash.
     *
     * <pre>
     * C:\a\b\c.txt --&gt; C:\a\b\
     * ~/a/b/c.txt  --&gt; ~/a/b/
     * a.txt        --&gt; ""
     * a/b/c        --&gt; a/b/
     * a/b/c/       --&gt; a/b/c/
     * C:           --&gt; C:
     * C:\          --&gt; C:\
     * ~            --&gt; ~/
     * ~/           --&gt; ~/
     * ~user        --&gt; ~user/
     * ~user/       --&gt; ~user/
     * </pre>
     * <p>
     * The output will be the same irrespective of the machine that the code is
     * running on.
     *
     * @param filename the filename to query, null returns null
     * @return the path of the file, an empty string if none exists, null if invalid
     */
    public static String getFullPath(final String filename) {
        return doGetFullPath(filename, true);
    }

    /**
     * Gets the full path from a full filename, which is the prefix + path, and also
     * excluding the final directory separator.
     * <p>
     * This method will handle a file in either Unix or Windows format. The method
     * is entirely text based, and returns the text before the last forward or
     * backslash.
     *
     * <pre>
     * C:\a\b\c.txt --&gt; C:\a\b
     * ~/a/b/c.txt  --&gt; ~/a/b
     * a.txt        --&gt; ""
     * a/b/c        --&gt; a/b
     * a/b/c/       --&gt; a/b/c
     * C:           --&gt; C:
     * C:\          --&gt; C:\
     * ~            --&gt; ~
     * ~/           --&gt; ~
     * ~user        --&gt; ~user
     * ~user/       --&gt; ~user
     * </pre>
     * <p>
     * The output will be the same irrespective of the machine that the code is
     * running on.
     *
     * @param filename the filename to query, null returns null
     * @return the path of the file, an empty string if none exists, null if invalid
     */
    public static String getFullPathNoEndSeparator(final String filename) {
        return doGetFullPath(filename, false);
    }

    /**
     * Does the work of getting the path.
     *
     * @param filename         the filename
     * @param includeSeparator true to include the end separator
     * @return the path
     */
    private static String doGetFullPath(final String filename, final boolean includeSeparator) {
        if (filename == null) {
            return null;
        }
        final var prefix = getPrefixLength(filename);
        if (prefix < 0) {
            return null;
        }
        if (prefix >= filename.length()) {
            if (includeSeparator) {
                return getPrefix(filename); // add end slash if necessary
            }
            return filename;
        }
        final var index = indexOfLastSeparator(filename);
        if (index < 0) {
            return filename.substring(0, prefix);
        }
        var end = index + (includeSeparator ? 1 : 0);
        if (end == 0) {
            end++;
        }
        return filename.substring(0, end);
    }

    /**
     * Gets the name minus the path from a full filename.
     * <p>
     * This method will handle a file in either Unix or Windows format. The text
     * after the last forward or backslash is returned.
     *
     * <pre>
     * a/b/c.txt --&gt; c.txt
     * a.txt     --&gt; a.txt
     * a/b/c     --&gt; c
     * a/b/c/    --&gt; ""
     * </pre>
     * <p>
     * The output will be the same irrespective of the machine that the code is
     * running on.
     *
     * @param filename the filename to query, null returns null
     * @return the name of the file without the path, or an empty string if none
     *         exists. Null bytes inside string will be removed
     */
    public static String getName(final String filename) {
        if (filename == null) {
            return null;
        }
        failIfNullBytePresent(filename);
        final var index = indexOfLastSeparator(filename);
        return filename.substring(index + 1);
    }

    /**
     * Check the input for null bytes, a sign of unsanitized data being passed to
     * file level functions.
     * <p>
     * This may be used for poison byte attacks.
     *
     * @param path the path to check
     */
    private static void failIfNullBytePresent(final String path) {
        final var len = path.length();
        for (var i = 0; i < len; i++) {
            if (path.charAt(i) == 0) {
                throw new IllegalArgumentException("""
                        Null byte present in file/path name. There are no \
                        known legitimate use cases for such data, but several injection attacks may use it\
                        """);
            }
        }
    }

    /**
     * Gets the base name, minus the full path and extension, from a full filename.
     * <p>
     * This method will handle a file in either Unix or Windows format. The text
     * after the last forward or backslash and before the last dot is returned.
     *
     * <pre>
     * a/b/c.txt --&gt; c
     * a.txt     --&gt; a
     * a/b/c     --&gt; c
     * a/b/c/    --&gt; ""
     * </pre>
     * <p>
     * The output will be the same irrespective of the machine that the code is
     * running on.
     *
     * @param filename the filename to query, null returns null
     * @return the name of the file without the path, or an empty string if none
     *         exists. Null bytes inside string will be removed
     */
    public static String getBaseName(final String filename) {
        return removeExtension(getName(filename));
    }

    /**
     * Gets the extension of a filename.
     * <p>
     * This method returns the textual part of the filename after the last dot.
     * There must be no directory separator after the dot.
     *
     * <pre>
     * foo.txt      --&gt; "txt"
     * a/b/c.jpg    --&gt; "jpg"
     * a/b.txt/c    --&gt; ""
     * a/b/c        --&gt; ""
     * </pre>
     * <p>
     * The output will be the same irrespective of the machine that the code is
     * running on.
     *
     * @param filename the filename to retrieve the extension of.
     * @return the extension of the file or an empty string if none exists or
     *         {@code null} if the filename is {@code null}.
     */
    public static String getExtension(final String filename) {
        if (filename == null) {
            return null;
        }
        final var index = indexOfExtension(filename);
        if (index == NOT_FOUND) {
            return "";
        }
        return filename.substring(index + 1);
    }

    // -----------------------------------------------------------------------
    /**
     * Removes the extension from a filename.
     * <p>
     * This method returns the textual part of the filename before the last dot.
     * There must be no directory separator after the dot.
     *
     * <pre>
     * foo.txt    --&gt; foo
     * a\b\c.jpg  --&gt; a\b\c
     * a\b\c      --&gt; a\b\c
     * a.b\c      --&gt; a.b\c
     * </pre>
     * <p>
     * The output will be the same irrespective of the machine that the code is
     * running on.
     *
     * @param filename the filename to query, null returns null
     * @return the filename minus the extension
     */
    public static String removeExtension(final String filename) {
        if (filename == null) {
            return null;
        }
        failIfNullBytePresent(filename);

        final var index = indexOfExtension(filename);
        if (index == NOT_FOUND) {
            return filename;
        }
        return filename.substring(0, index);
    }

    // -----------------------------------------------------------------------
    /**
     * Checks whether two filenames are equal exactly.
     * <p>
     * No processing is performed on the filenames other than comparison, thus this
     * is merely a null-safe case-sensitive equals.
     *
     * @param filename1 the first filename to query, may be null
     * @param filename2 the second filename to query, may be null
     * @return true if the filenames are equal, null equals null
     */
    public static boolean equals(final String filename1, final String filename2) {
        return equals(filename1, filename2, false, IOCase.SENSITIVE);
    }

    /**
     * Checks whether two filenames are equal using the case rules of the system.
     * <p>
     * No processing is performed on the filenames other than comparison. The check
     * is case-sensitive on Unix and case-insensitive on Windows.
     *
     * @param filename1 the first filename to query, may be null
     * @param filename2 the second filename to query, may be null
     * @return true if the filenames are equal, null equals null
     */
    public static boolean equalsOnSystem(final String filename1, final String filename2) {
        return equals(filename1, filename2, false, IOCase.SYSTEM);
    }

    // -----------------------------------------------------------------------
    /**
     * Checks whether two filenames are equal after both have been normalized.
     * <p>
     * Both filenames are first passed to {@link #normalize(String)}. The check is
     * then performed in a case-sensitive manner.
     *
     * @param filename1 the first filename to query, may be null
     * @param filename2 the second filename to query, may be null
     * @return true if the filenames are equal, null equals null
     */
    public static boolean equalsNormalized(final String filename1, final String filename2) {
        return equals(filename1, filename2, true, IOCase.SENSITIVE);
    }

    /**
     * Checks whether two filenames are equal after both have been normalized and
     * using the case rules of the system.
     * <p>
     * Both filenames are first passed to {@link #normalize(String)}. The check is
     * then performed case-sensitive on Unix and case-insensitive on Windows.
     *
     * @param filename1 the first filename to query, may be null
     * @param filename2 the second filename to query, may be null
     * @return true if the filenames are equal, null equals null
     */
    public static boolean equalsNormalizedOnSystem(final String filename1, final String filename2) {
        return equals(filename1, filename2, true, IOCase.SYSTEM);
    }

    /**
     * Checks whether two filenames are equal, optionally normalizing and providing
     * control over the case-sensitivity.
     *
     * @param filename1       the first filename to query, may be null
     * @param filename2       the second filename to query, may be null
     * @param normalized      whether to normalize the filenames
     * @param caseSensitivity what case sensitivity rule to use, null means
     *                        case-sensitive
     * @return true if the filenames are equal, null equals null
     */
    public static boolean equals(String filename1, String filename2, final boolean normalized, IOCase caseSensitivity) {

        if (filename1 == null || filename2 == null) {
            return filename1 == null && filename2 == null;
        }
        if (normalized) {
            filename1 = normalize(filename1);
            filename2 = normalize(filename2);
            if (filename1 == null || filename2 == null) {
                throw new NullPointerException("Error normalizing one or both of the file names");
            }
        }
        if (caseSensitivity == null) {
            caseSensitivity = IOCase.SENSITIVE;
        }
        return caseSensitivity.checkEquals(filename1, filename2);
    }

    // -----------------------------------------------------------------------
    /**
     * Checks whether the extension of the filename is that specified.
     * <p>
     * This method obtains the extension as the textual part of the filename after
     * the last dot. There must be no directory separator after the dot. The
     * extension check is case-sensitive always.
     *
     * @param filename  the filename to query, null returns false
     * @param extension the extension to check for, null or empty checks for no
     *                  extension
     * @return true if the filename has the specified extension
     * @throws java.lang.IllegalArgumentException if the supplied filename contains
     *                                            null bytes
     */
    public static boolean isExtension(final String filename, final String extension) {
        if (filename == null) {
            return false;
        }
        failIfNullBytePresent(filename);

        if (extension == null || extension.isEmpty()) {
            return indexOfExtension(filename) == NOT_FOUND;
        }
        final var fileExt = getExtension(filename);
        return fileExt.equals(extension);
    }

    /**
     * Checks whether the extension of the filename is one of those specified.
     * <p>
     * This method obtains the extension as the textual part of the filename after
     * the last dot. There must be no directory separator after the dot. The
     * extension check is case-sensitive on all platforms.
     *
     * @param filename   the filename to query, null returns false
     * @param extensions the extensions to check for, null checks for no extension
     * @return true if the filename is one of the extensions
     * @throws java.lang.IllegalArgumentException if the supplied filename contains
     *                                            null bytes
     */
    public static boolean isExtension(final String filename, final String... extensions) {
        if (filename == null) {
            return false;
        }
        failIfNullBytePresent(filename);

        if (extensions == null || extensions.length == 0) {
            return indexOfExtension(filename) == NOT_FOUND;
        }
        final var fileExt = getExtension(filename);
        for (final String extension : extensions) {
            if (fileExt.equals(extension)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks whether the extension of the filename is one of those specified.
     * <p>
     * This method obtains the extension as the textual part of the filename after
     * the last dot. There must be no directory separator after the dot. The
     * extension check is case-sensitive on all platforms.
     *
     * @param filename   the filename to query, null returns false
     * @param extensions the extensions to check for, null checks for no extension
     * @return true if the filename is one of the extensions
     * @throws java.lang.IllegalArgumentException if the supplied filename contains
     *                                            null bytes
     */
    public static boolean isExtension(final String filename, final Collection<String> extensions) {
        if (filename == null) {
            return false;
        }
        failIfNullBytePresent(filename);

        if (extensions == null || extensions.isEmpty()) {
            return indexOfExtension(filename) == NOT_FOUND;
        }
        final var fileExt = getExtension(filename);
        for (final String extension : extensions) {
            if (fileExt.equals(extension)) {
                return true;
            }
        }
        return false;
    }

    // -----------------------------------------------------------------------
    /**
     * Checks a filename to see if it matches the specified wildcard matcher, always
     * testing case-sensitive.
     * <p>
     * The wildcard matcher uses the characters '?' and '*' to represent a single or
     * multiple (zero or more) wildcard characters. This is the same as often found
     * on Dos/Unix command lines. The check is case-sensitive always.
     *
     * <pre>
     * wildcardMatch("c.txt", "*.txt")      --&gt; true
     * wildcardMatch("c.txt", "*.jpg")      --&gt; false
     * wildcardMatch("a/b/c.txt", "a/b/*")  --&gt; true
     * wildcardMatch("c.txt", "*.???")      --&gt; true
     * wildcardMatch("c.txt", "*.????")     --&gt; false
     * </pre>
     *
     * N.B. the sequence "*?" does not work properly at present in match strings.
     *
     * @param filename        the filename to match on
     * @param wildcardMatcher the wildcard string to match against
     * @return true if the filename matches the wildcard string
     */
    public static boolean wildcardMatch(final String filename, final String wildcardMatcher) {
        return wildcardMatch(filename, wildcardMatcher, IOCase.SENSITIVE);
    }

    /**
     * Checks a filename to see if it matches the specified wildcard matcher using
     * the case rules of the system.
     * <p>
     * The wildcard matcher uses the characters '?' and '*' to represent a single or
     * multiple (zero or more) wildcard characters. This is the same as often found
     * on Dos/Unix command lines. The check is case-sensitive on Unix and
     * case-insensitive on Windows.
     *
     * <pre>
     * wildcardMatch("c.txt", "*.txt")      --&gt; true
     * wildcardMatch("c.txt", "*.jpg")      --&gt; false
     * wildcardMatch("a/b/c.txt", "a/b/*")  --&gt; true
     * wildcardMatch("c.txt", "*.???")      --&gt; true
     * wildcardMatch("c.txt", "*.????")     --&gt; false
     * </pre>
     *
     * N.B. the sequence "*?" does not work properly at present in match strings.
     *
     * @param filename        the filename to match on
     * @param wildcardMatcher the wildcard string to match against
     * @return true if the filename matches the wildcard string
     */
    public static boolean wildcardMatchOnSystem(final String filename, final String wildcardMatcher) {
        return wildcardMatch(filename, wildcardMatcher, IOCase.SYSTEM);
    }

    /**
     * Checks a filename to see if it matches the specified wildcard matcher
     * allowing control over case-sensitivity.
     * <p>
     * The wildcard matcher uses the characters '?' and '*' to represent a single or
     * multiple (zero or more) wildcard characters. N.B. the sequence "*?" does not
     * work properly at present in match strings.
     *
     * @param filename        the filename to match on
     * @param wildcardMatcher the wildcard string to match against
     * @param caseSensitivity what case sensitivity rule to use, null means
     *                        case-sensitive
     * @return true if the filename matches the wildcard string
     */
    @SuppressWarnings({"squid:S3776", "squid:S135"}) // owolff: original code
    public static boolean wildcardMatch(final String filename, final String wildcardMatcher, IOCase caseSensitivity) {
        if (filename == null && wildcardMatcher == null) {
            return true;
        }
        if (filename == null || wildcardMatcher == null) {
            return false;
        }
        if (caseSensitivity == null) {
            caseSensitivity = IOCase.SENSITIVE;
        }
        final var wcs = splitOnTokens(wildcardMatcher);
        var anyChars = false;
        var textIdx = 0;
        var wcsIdx = 0;
        final Deque<int[]> backtrack = new ArrayDeque<>();

        // loop around a backtrack stack, to handle complex * matching
        do {
            if (!backtrack.isEmpty()) {
                final var array = backtrack.pop();
                wcsIdx = array[0];
                textIdx = array[1];
                anyChars = true;
            }

            // loop whilst tokens and text left to process
            while (wcsIdx < wcs.length) {

                if ("?".equals(wcs[wcsIdx])) {
                    // ? so move to next text char
                    textIdx++;
                    if (textIdx > filename.length()) {
                        break;
                    }
                    anyChars = false;

                } else if ("*".equals(wcs[wcsIdx])) {
                    // set any chars status
                    anyChars = true;
                    if (wcsIdx == wcs.length - 1) {
                        textIdx = filename.length();
                    }

                } else {
                    // matching text token
                    if (anyChars) {
                        // any chars then try to locate text token
                        textIdx = caseSensitivity.checkIndexOf(filename, textIdx, wcs[wcsIdx]);
                        if (textIdx == NOT_FOUND) {
                            // token not found
                            break;
                        }
                        final var repeat = caseSensitivity.checkIndexOf(filename, textIdx + 1, wcs[wcsIdx]);
                        if (repeat >= 0) {
                            backtrack.push(new int[]{wcsIdx, repeat});
                        }
                    } else // matching from current position
                        if (!caseSensitivity.checkRegionMatches(filename, textIdx, wcs[wcsIdx])) {
                            // couldn't match token
                            break;
                        }

                    // matched text token, move text index to end of matched token
                    textIdx += wcs[wcsIdx].length();
                    anyChars = false;
                }

                wcsIdx++;
            }

            // full match
            if (wcsIdx == wcs.length && textIdx == filename.length()) {
                return true;
            }

        } while (!backtrack.isEmpty());

        return false;
    }

    /**
     * Splits a string into a number of tokens. The text is split by '?' and '*'.
     * Where multiple '*' occur consecutively they are collapsed into a single '*'.
     *
     * @param text the text to split
     * @return the array of tokens, never null
     */
    static String[] splitOnTokens(final String text) {
        // used by wildcardMatch
        // package level so a unit test may run on this

        if (text.indexOf('?') == NOT_FOUND && text.indexOf('*') == NOT_FOUND) {
            return new String[]{text};
        }

        final var array = text.toCharArray();
        final var list = new ArrayList<String>();
        final var buffer = new StringBuilder();
        char prevChar = 0;
        for (final char ch : array) {
            if (ch == '?' || ch == '*') {
                if (!buffer.isEmpty()) {
                    list.add(buffer.toString());
                    buffer.setLength(0);
                }
                if (ch == '?') {
                    list.add("?");
                } else if (prevChar != '*') {// ch == '*' here; check if previous char was '*'
                    list.add("*");
                }
            } else {
                buffer.append(ch);
            }
            prevChar = ch;
        }
        if (!buffer.isEmpty()) {
            list.add(buffer.toString());
        }

        return list.toArray(new String[0]);
    }

}
