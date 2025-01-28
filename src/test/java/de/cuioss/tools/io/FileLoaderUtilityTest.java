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

import static de.cuioss.tools.io.FileLoaderUtility.copyFileToTemp;
import static de.cuioss.tools.io.FileLoaderUtility.getLoaderForPath;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;

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
    void shouldReturnLoaderForPaths() {
        assertEquals(ClassPathLoader.class, getLoaderForPath(FileTypePrefix.CLASSPATH + EXISTING_FILE_NAME).getClass());
        assertEquals(FileSystemLoader.class, getLoaderForPath(FileTypePrefix.FILE + EXISTING_FILE_NAME).getClass());
        assertEquals(FileSystemLoader.class, getLoaderForPath(EXISTING_FILE_NAME).getClass());
        assertEquals(FileSystemLoader.class, getLoaderForPath(NOT_EXISTING_FILE).getClass());
    }

    @Test
    void shouldReturnContentAsString() throws IOException {
        var loaded = FileLoaderUtility.toString(LOADER_EXISTING_FILE_CLASSPATH);
        assertNotNull(loaded);
        assertFalse(loaded.isEmpty());
        assertTrue(loaded.contains("Hello"));

        assertThrows(IllegalArgumentException.class, () -> {
            FileLoaderUtility.toStringUnchecked(LOADER_NOT_EXISTING_FILE);
        });
    }

}
