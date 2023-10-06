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
package de.cuioss.tools.io;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;

import org.junit.jupiter.api.Test;

class FileSystemLoaderTest {

    private static final String EXISTING_FILE = "pom.xml";

    private static final String EXISTING_EXTERNAL_FILE = "external:/pom.xml";

    private static final String NOT_EXISTING_FILE = "notThere.txt";

    private static final String EXISTING_DIRECTORY = "src";

    private static final String EXISTING_EXTERNAL_DIRECTORY = "external:/src";

    private static final String EXISTING_FILE_PATH = Paths.get(EXISTING_FILE).toAbsolutePath().toString();

    private static final String EXISTING_DIRECTORY_PATH = Paths.get(EXISTING_DIRECTORY).toAbsolutePath().toString();

    private static final String NOT_EXISTING_FILE_PATH = Paths.get(NOT_EXISTING_FILE).toAbsolutePath().toString();

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
        final var loader = new FileSystemLoader(Paths.get(EXISTING_FILE_PATH));
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
        assertThrows(IllegalArgumentException.class, () -> {
            FileSystemLoader.checkPathName(prefix);
        });
    }

    @Test
    void shouldHandleFilePrefixedPath() throws IOException {
        assertEquals(new File(EXISTING_FILE).getCanonicalPath(),
                FileSystemLoader.checkPathName(FileTypePrefix.FILE + EXISTING_FILE));
    }

    @Test
    void shouldFailToLoadNotExistingFile() {
        var fileSystemLoader = new FileSystemLoader(NOT_EXISTING_FILE_PATH);
        assertThrows(IllegalStateException.class, () -> {
            fileSystemLoader.inputStream();
        });
    }
}
