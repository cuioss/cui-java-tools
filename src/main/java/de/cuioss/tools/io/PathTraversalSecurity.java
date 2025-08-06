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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;

/**
 * Utility class for path traversal security validation and secure file operations.
 * This class provides methods to validate path segments against path traversal attacks
 * and create temporary files with secure permissions.
 *
 * @author Oliver Wolff
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class PathTraversalSecurity {

    /**
     * Validates that a path segment does not contain dangerous characters or sequences.
     * This method is used to prevent path traversal attacks by ensuring that filename parts don't contain
     * path traversal sequences or separators that could be used to escape the intended directory.
     *
     * @param pathSegment the path segment to validate (can be null)
     * @throws IllegalArgumentException if the path segment contains invalid characters or sequences
     */
    public static void validatePathSegment(String pathSegment) {
        if (pathSegment != null &&
                (pathSegment.contains("..") || pathSegment.contains("/") || pathSegment.contains("\\"))) {
            throw new IllegalArgumentException("Invalid path segment: potential path traversal detected in '" + pathSegment + "'");
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
    public static Path createSecureTempFile(String prefix, String suffix) throws IOException {
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