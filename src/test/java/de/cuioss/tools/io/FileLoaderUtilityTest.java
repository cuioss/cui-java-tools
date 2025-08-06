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

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import static de.cuioss.tools.io.FileLoaderUtility.*;
import static de.cuioss.tools.io.PathTraversalSecurity.validatePathSegment;
import static org.junit.jupiter.api.Assertions.*;

@SuppressWarnings("DataFlowIssue")
class FileLoaderUtilityTest {

    public static final String EXISTING_FILE_NAME = "/META-INF/someTestFile.txt";

    private static final FileLoader LOADER_EXISTING_FILE_CLASSPATH = new ClassPathLoader(EXISTING_FILE_NAME);

    private static final String NOT_EXISTING_FILE = "/not/there.cui";

    private static final FileLoader LOADER_NOT_EXISTING_FILE = new ClassPathLoader(NOT_EXISTING_FILE);

    @Test
    void copyShouldFailOnEmptyLoader() {
        assertThrows(IllegalArgumentException.class, () -> copyFileToTemp(null, true));
    }

    @Test
    void copyShouldFailOnNotExistingFile() {
        assertThrows(IllegalArgumentException.class, () -> copyFileToTemp(LOADER_NOT_EXISTING_FILE, true));
    }

    @Test
    void shouldCopyExistingFile() throws IOException {
        final var copy = copyFileToTemp(LOADER_EXISTING_FILE_CLASSPATH, true);
        assertNotNull(copy);
        assertTrue(Files.exists(copy));
        final var size = Files.size(copy);
        assertTrue(size > 40);
    }

    @Test
    void shouldFailToProvideLoaderOnNull() {
        assertThrows(IllegalArgumentException.class, () -> getLoaderForPath(null));
    }

    @Test
    void shouldFailToProvideLoaderOnEmpty() {
        assertThrows(IllegalArgumentException.class, () -> getLoaderForPath(""));
    }

    @Test
    void shouldReturnLoaderForPaths() {
        assertEquals(ClassPathLoader.class, getLoaderForPath(FileTypePrefix.CLASSPATH + EXISTING_FILE_NAME).getClass());
        assertEquals(FileSystemLoader.class, getLoaderForPath(FileTypePrefix.FILE + EXISTING_FILE_NAME).getClass());
        assertEquals(FileSystemLoader.class, getLoaderForPath(EXISTING_FILE_NAME).getClass());
        assertEquals(FileSystemLoader.class, getLoaderForPath(NOT_EXISTING_FILE).getClass());
    }

    @Test
    void shouldReturnUrlLoaderForUrlPrefix() {
        assertEquals(UrlLoader.class, getLoaderForPath("url:http://example.com/file.txt").getClass());
    }

    @Test
    void shouldReturnContentAsString() throws IOException {
        var loaded = FileLoaderUtility.toString(LOADER_EXISTING_FILE_CLASSPATH);
        assertNotNull(loaded);
        assertFalse(loaded.isEmpty());
        assertTrue(loaded.contains("Hello"));
    }

    @Test
    void shouldReturnContentAsStringUnchecked() {
        // Test successful case - should return content without throwing
        var loaded = FileLoaderUtility.toStringUnchecked(LOADER_EXISTING_FILE_CLASSPATH);
        assertNotNull(loaded);
        assertFalse(loaded.isEmpty());
        assertTrue(loaded.contains("Hello"));

        // Test error case - should throw IllegalArgumentException
        assertThrows(IllegalArgumentException.class, () ->
                FileLoaderUtility.toStringUnchecked(LOADER_NOT_EXISTING_FILE));
    }

    @Test
    void shouldReturnContentAsStringWithCharset() throws IOException {
        var loaded = FileLoaderUtility.toString(LOADER_EXISTING_FILE_CLASSPATH, StandardCharsets.UTF_8);
        assertNotNull(loaded);
        assertFalse(loaded.isEmpty());
        assertTrue(loaded.contains("Hello"));
    }

    @Test
    void shouldThrowOnNullFileLoader() {
        assertThrows(NullPointerException.class, () -> FileLoaderUtility.toString(null));
        assertThrows(NullPointerException.class, () -> FileLoaderUtility.toString(null, StandardCharsets.UTF_8));
        assertThrows(NullPointerException.class, () -> FileLoaderUtility.toStringUnchecked(null));
    }

    @Test
    void validatePathSegmentShouldAcceptValidSegments() {
        // Should not throw for valid segments
        assertDoesNotThrow(() -> validatePathSegment(null));
        assertDoesNotThrow(() -> validatePathSegment(""));
        assertDoesNotThrow(() -> validatePathSegment("normal.txt"));
        assertDoesNotThrow(() -> validatePathSegment("file-name_123.pdf"));
        assertDoesNotThrow(() -> validatePathSegment(".hidden"));
        assertDoesNotThrow(() -> validatePathSegment("file with spaces.doc"));
    }

    @Test
    void validatePathSegmentShouldRejectPathTraversal() {
        // Should throw for path traversal attempts
        assertThrows(IllegalArgumentException.class,
                () -> validatePathSegment(".."),
                "Should reject double dots");

        assertThrows(IllegalArgumentException.class,
                () -> validatePathSegment("../etc/passwd"),
                "Should reject path traversal with forward slash");

        assertThrows(IllegalArgumentException.class,
                () -> validatePathSegment("..\\windows\\system32"),
                "Should reject path traversal with backslash");

        assertThrows(IllegalArgumentException.class,
                () -> validatePathSegment("normal/../../../etc/passwd"),
                "Should reject embedded path traversal");

        assertThrows(IllegalArgumentException.class,
                () -> validatePathSegment("/etc/passwd"),
                "Should reject absolute paths with forward slash");

        assertThrows(IllegalArgumentException.class,
                () -> validatePathSegment("C:\\Windows\\System32"),
                "Should reject Windows absolute paths");

        assertThrows(IllegalArgumentException.class,
                () -> validatePathSegment("some/nested/path"),
                "Should reject nested paths with forward slash");

        assertThrows(IllegalArgumentException.class,
                () -> validatePathSegment("some\\nested\\path"),
                "Should reject nested paths with backslash");
    }

}
