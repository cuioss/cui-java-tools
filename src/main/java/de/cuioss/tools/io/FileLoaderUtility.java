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

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;

import static de.cuioss.tools.base.Preconditions.checkArgument;
import static de.cuioss.tools.string.MoreStrings.isEmpty;
import static java.util.Objects.requireNonNull;

/**
 * Utility class for dealing with generic / classpath related file access.
 *
 * @author Oliver Wolff
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class FileLoaderUtility {

    /**
     * Returns an implementation of {@link FileLoader} matching to the given path.
     *
     * @param pathName must not be null or empty.
     * @return a configured implementation of {@link FileLoader}. In case the
     *         pathName is prefixed with {@link FileTypePrefix#CLASSPATH} it returns
     *         a {@link ClassPathLoader}. If prefixed with
     *         {@link FileTypePrefix#URL} it returns a {@link UrlLoader}. Otherwise,
     *         it returns a {@link FileSystemLoader}.
     */
    public static FileLoader getLoaderForPath(final String pathName) {
        if (isEmpty(pathName)) {
            throw new IllegalArgumentException("pathName must not be null nor empty");
        }
        if (pathName.startsWith(FileTypePrefix.CLASSPATH.getPrefix())) {
            return new ClassPathLoader(pathName);
        }
        if (pathName.startsWith(FileTypePrefix.URL.getPrefix())) {
            return new UrlLoader(pathName);
        }
        return new FileSystemLoader(pathName);
    }

    /**
     * Helper class that copies the content of a {@link FileLoader} to the
     * temp-folder and references it
     * <h2>Caution: Security-Impact</h2> Creating a temp-file might introduce a
     * security issue. Never ever use this location for sensitive information that
     * might be of interest for an attacker
     * 
     * <h2>Security Note</h2> This method validates that the source file name does not
     * contain path traversal sequences to prevent unauthorized access to files outside
     * the intended directory structure.
     *
     * @param source           must not be null and represent an accessible file,
     *                         saying {@link FileLoader#isReadable()}
     * @param markDeleteOnExit if <code>true</code> the file will be marked to
     *                         delete on Exit.
     * @return a reference on a file copied in the temp folder
     * @throws IOException
     */
    public static Path copyFileToTemp(final FileLoader source, final boolean markDeleteOnExit) throws IOException {
        checkArgument(null != source, "Attribute with name source must not be null");
        checkArgument(source.isReadable(), "Source must be readable");

        // Validate filename to prevent path traversal
        var fileName = source.getFileName();
        var namePart = fileName.getNamePart();
        var suffix = fileName.getSuffix();

        // Ensure the filename parts don't contain path separators or traversal sequences
        if (namePart.contains("..") || namePart.contains("/") || namePart.contains("\\") ||
                (suffix != null && (suffix.contains("..") || suffix.contains("/") || suffix.contains("\\")))) {
            throw new IllegalArgumentException("Invalid filename: potential path traversal detected");
        }

        // Create temp file with secure permissions (owner read/write only)
        // This addresses SonarQube security warning about publicly writable directories
        final Path target = createSecureTempFile(namePart, suffix);

        try (final var inputStream = source.inputStream()) {
            Files.copy(new BufferedInputStream(inputStream), target, StandardCopyOption.REPLACE_EXISTING);
        }
        if (markDeleteOnExit) {
            target.toFile().deleteOnExit();
        }
        return target;
    }

    /**
     * Convenience method for reading the content from a given {@link FileLoader}
     * into a String
     *
     * @param fileLoader must not be null
     * @param charset    must not be null
     * @return The String content of the File represented by the given
     *         {@link FileLoader}
     * @throws IOException if an I/O error occurs while reading the file
     */
    public static String toString(final FileLoader fileLoader, final Charset charset) throws IOException {
        requireNonNull(fileLoader);
        final var writer = new StringWriter();
        try (final var inputStream = fileLoader.inputStream()) {
            IOStreams.copy(inputStream, writer, charset);
        }
        return writer.toString();
    }

    /**
     * Convenience method for reading the content from a given {@link FileLoader}
     * into a String read as UTF-8 String
     *
     * @param fileLoader must not be null
     * @return The String content of the File represented by the given
     *         {@link FileLoader}
     * @throws IOException if an I/O error occurs while reading the file
     */
    public static String toString(final FileLoader fileLoader) throws IOException {
        return toString(fileLoader, StandardCharsets.UTF_8);
    }

    /**
     * Convenience method for reading the content from a given {@link FileLoader}
     * into a String read as UTF-8 String
     *
     * @param fileLoader must not be null
     * @return The String content of the File represented by the given
     *         {@link FileLoader}
     * @throws IllegalArgumentException masking the actual {@link IOException}
     * @throws NullPointerException     if <code>fileLoader</code> is null
     */
    public static String toStringUnchecked(final FileLoader fileLoader) {
        requireNonNull(fileLoader);
        try {
            return toString(fileLoader);
        } catch (final IOException | IllegalStateException e) {
            throw new IllegalArgumentException("Unable to read from Path " + fileLoader.getFileName(), e);
        }
    }

    /**
     * Creates a temporary file with secure permissions.
     * On POSIX systems (Unix/Linux/Mac), sets permissions to owner-only (rw-------).
     * On Windows, relies on default temp file security.
     *
     * @param prefix the prefix string to be used in generating the file name
     * @param suffix the suffix string to be used in generating the file name
     * @return Path to the created temporary file
     * @throws IOException if an I/O error occurs
     */
    @SuppressWarnings("java:S5443")
    // Sonar: "Make sure publicly writable directories are used safely" - False positive.
    // We explicitly set restrictive permissions (rw-------) on POSIX systems.
    // On Windows, temp files are created in user-specific directories with appropriate ACLs.
    // Additionally, the filename parameters are validated against path traversal attacks before this method is called.
    static Path createSecureTempFile(String prefix, String suffix) throws IOException {
        try {
            // Try to set POSIX permissions (works on Unix/Linux/Mac)
            Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-------");
            var attrs = PosixFilePermissions.asFileAttribute(perms);
            return Files.createTempFile(prefix, suffix, attrs);
        } catch (UnsupportedOperationException e) {
            // Fallback for Windows and other non-POSIX systems
            // Windows handles file permissions differently, temp files are created with user-only access by default
            // This is considered safe as Windows temp files are created in user-specific temp directories
            @SuppressWarnings("java:S5443") // Already addressed - see method-level documentation
            Path tempFile = Files.createTempFile(prefix, suffix);
            return tempFile;
        }
    }
}
