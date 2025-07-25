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
import java.net.URL;

import static org.junit.jupiter.api.Assertions.*;

class UrlLoaderTest {

    @Test
    void shouldHandlePrefix() {
        assertDoesNotThrow(() -> new UrlLoader("url:file:/foo/bar"));
        assertDoesNotThrow(() -> new UrlLoader("file:/foo/bar"));
    }

    @Test
    void shouldHandleInvalidUrl() {
        assertThrows(IllegalArgumentException.class, () -> new UrlLoader("invalid:url:format"));
        assertThrows(IllegalArgumentException.class, () -> new UrlLoader("://invalid"));
    }

    @Test
    void shouldHandleNullUrl() {
        assertThrows(IllegalArgumentException.class, () -> new UrlLoader((URL) null));
        assertThrows(IllegalArgumentException.class, () -> new UrlLoader((String) null));
    }

    @Test
    void shouldHandleNonExistentResource() {
        var loader = new UrlLoader("file:/non/existent/file.txt");
        assertFalse(loader.isReadable());
        assertThrows(IOException.class, loader::inputStream);
    }

    @Test
    void shouldHandleValidResource() throws IOException {
        var url = UrlLoaderTest.class.getResource("/someTestFile.txt");
        assertNotNull(url, "Test resource not found");

        var loader = new UrlLoader(url);
        assertTrue(loader.isReadable());

        var stream = loader.inputStream();
        assertNotNull(stream);
        stream.close();
    }

    @Test
    void shouldGetCorrectFileName() {
        var loader = new UrlLoader("file:/path/to/test.txt");
        var filename = loader.getFileName();
        assertEquals("test.txt", filename.getOriginalName());
        assertEquals("txt", filename.getSuffix());
    }

    @Test
    void shouldNotBeFilesystemLoader() {
        var loader = new UrlLoader("file:/some/path");
        assertFalse(loader.isFilesystemLoader());
    }

    @Test
    void shouldImplementEqualsAndHashCode() {
        var loader1 = new UrlLoader("file:/test/path");
        var loader2 = new UrlLoader("file:/test/path");
        var loader3 = new UrlLoader("file:/different/path");

        assertEquals(loader1, loader2);
        assertEquals(loader1.hashCode(), loader2.hashCode());
        assertNotEquals(loader1, loader3);
        assertNotEquals(loader1.hashCode(), loader3.hashCode());
    }

    @Test
    void niceToString() {
        final var result = new UrlLoader(UrlLoaderTest.class.getResource("/someTestFile.txt")).toString();
        assertTrue(result.startsWith("UrlLoader(url=file:"));
        assertTrue(result.endsWith("someTestFile.txt)"));
    }

    @Test
    void shouldHandleUrlWithQuery() {
        var loader = new UrlLoader("file:/path/file.txt?param=value");
        assertEquals("file.txt", loader.getFileName().getOriginalName());
    }
}
