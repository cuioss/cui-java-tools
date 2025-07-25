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

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class FileSystemLoaderTest {

    private static final String EXISTING_FILE = "pom.xml";

    private static final String EXISTING_EXTERNAL_FILE = "external:/pom.xml";

    private static final String NOT_EXISTING_FILE = "notThere.txt";

    private static final String EXISTING_DIRECTORY = "src";

    private static final String EXISTING_EXTERNAL_DIRECTORY = "external:/src";

    private static final String EXISTING_FILE_PATH = Path.of(EXISTING_FILE).toAbsolutePath().toString();

    private static final String EXISTING_DIRECTORY_PATH = Path.of(EXISTING_DIRECTORY).toAbsolutePath().toString();

    private static final String NOT_EXISTING_FILE_PATH = Path.of(NOT_EXISTING_FILE).toAbsolutePath().toString();

    @Test
    void shouldHandleExistingFile() throws IOException {
        final var loader = new FileSystemLoader(EXISTING_FILE_PATH);
        assertTrue(loader.isReadable());
        assertTrue(loader.isFilesystemLoader());
        assertEquals(EXISTING_FILE, loader.getFileName().getOriginalName());
        assertNotNull(loader.inputStream());
    }

    @Test
    void shouldHandlePathAsArgument() throws IOException {
        final var loader = new FileSystemLoader(Path.of(EXISTING_FILE_PATH));
        assertTrue(loader.isReadable());
        assertTrue(loader.isFilesystemLoader());
        assertEquals(EXISTING_FILE, loader.getFileName().getOriginalName());
        assertNotNull(loader.inputStream());
    }

    @Test
    void shouldHandleExistingExternalFile() throws IOException {
        final var loader = new FileSystemLoader(EXISTING_EXTERNAL_FILE);
        assertTrue(loader.isReadable());
        assertTrue(loader.isFilesystemLoader());
        assertEquals(EXISTING_FILE, loader.getFileName().getOriginalName());
        assertNotNull(loader.inputStream());
    }

    @Test
    void shouldHandleExistingDirectory() {
        final var loader = new FileSystemLoader(EXISTING_DIRECTORY_PATH);
        assertFalse(loader.isReadable());
        assertEquals(EXISTING_DIRECTORY, loader.getFileName().getOriginalName());
    }

    @Test
    void shouldHandleExistingExternalDirectory() {
        final var loader = new FileSystemLoader(EXISTING_EXTERNAL_DIRECTORY);
        assertFalse(loader.isReadable());
        assertEquals(EXISTING_DIRECTORY, loader.getFileName().getOriginalName());
    }

    @Test
    void shouldHandleNotExistingFile() {
        final var loader = new FileSystemLoader(NOT_EXISTING_FILE_PATH);
        assertFalse(loader.isReadable());
        assertEquals(NOT_EXISTING_FILE, loader.getFileName().getOriginalName());
    }

    @Test
    void shouldNotHandleClasspathFile() {
        assertThrows(IllegalArgumentException.class,
                () -> FileSystemLoader.checkPathName(FileTypePrefix.CLASSPATH + EXISTING_FILE));
    }

    @Test
    void shouldNotHandleNullPathname() {
        assertThrows(IllegalArgumentException.class, () -> FileSystemLoader.checkPathName(null));
    }

    @Test
    void shouldNotHandleFileOnlyPathname() {
        var prefix = FileTypePrefix.FILE.getPrefix();
        assertThrows(IllegalArgumentException.class, () ->
                FileSystemLoader.checkPathName(prefix));
    }

    @Test
    void shouldHandleFilePrefixedPath() throws IOException {
        assertEquals(new File(EXISTING_FILE).getCanonicalPath(),
                FileSystemLoader.checkPathName(FileTypePrefix.FILE + EXISTING_FILE));
    }

    @Test
    void shouldFailToLoadNotExistingFile() {
        var fileSystemLoader = new FileSystemLoader(NOT_EXISTING_FILE_PATH);
        assertThrows(IllegalStateException.class, fileSystemLoader::inputStream);
    }

    @Test
    void shouldHandleOutputStreamForWritableFile() throws IOException {
        // Create a temporary file for testing
        File tempFile = File.createTempFile("test", ".txt");
        tempFile.deleteOnExit();

        var loader = new FileSystemLoader(tempFile.getAbsolutePath());
        assertTrue(loader.isWritable());

        try (var output = loader.outputStream()) {
            assertNotNull(output);
            output.write("test".getBytes());
        }
    }

    @Test
    void shouldFailOutputStreamForNonWritableFile() {
        var loader = new FileSystemLoader(NOT_EXISTING_FILE_PATH);
        assertFalse(loader.isWritable());
        assertThrows(IllegalStateException.class, loader::outputStream);
    }

    @Test
    void shouldFailOutputStreamForDirectory() {
        var loader = new FileSystemLoader(EXISTING_DIRECTORY_PATH);
        assertFalse(loader.isWritable());
        assertThrows(IllegalStateException.class, loader::outputStream);
    }

    @Test
    void shouldGetUrlForExistingFile() throws IOException {
        var loader = new FileSystemLoader(EXISTING_FILE_PATH);
        var url = loader.getURL();
        assertNotNull(url);
        assertEquals(Path.of(EXISTING_FILE_PATH).toUri().toURL(), url);
    }

    @Test
    void shouldGetUrlForNonExistentFile() throws MalformedURLException {
        var loader = new FileSystemLoader(NOT_EXISTING_FILE_PATH);
        var url = loader.getURL();
        assertNotNull(url);
        assertEquals(Path.of(NOT_EXISTING_FILE_PATH).toUri().toURL().getPath(), url.getPath());
    }
}
