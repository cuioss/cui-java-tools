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

import static org.junit.jupiter.api.Assertions.*;

class ClassPathLoaderTest {

    private static final String EXISTING_FILE_PATH = "/META-INF/someTestFile.txt";

    private static final String EXISTING_FILE_PATH_WO_SLASH = "META-INF/someTestFile.txt";

    private static final String EXISTING_CLASSPATH_FILE = FileTypePrefix.CLASSPATH + EXISTING_FILE_PATH;

    private static final String EXISTING_CLASSPATH_FILE_WO_SLASH = FileTypePrefix.CLASSPATH
            + EXISTING_FILE_PATH_WO_SLASH;

    private static final String JAR_LOCATED_CLASSPATH_FILE_NAME = FileTypePrefix.CLASSPATH
            + EXISTING_FILE_PATH_WO_SLASH;

    private static final String NOT_EXISTING_FILE = FilenameUtils.normalize("/not/there.cui");

    private static final String NOT_EXISTING_CLASSPATH_FILE = FileTypePrefix.CLASSPATH + NOT_EXISTING_FILE;

    @Test
    void shouldComputeCorrectClassPath() {
        var classpath = ClassPathLoader.checkClasspathName(EXISTING_CLASSPATH_FILE);
        assertEquals(EXISTING_FILE_PATH, classpath);

        classpath = ClassPathLoader.checkClasspathName(EXISTING_CLASSPATH_FILE_WO_SLASH);
        assertEquals(EXISTING_FILE_PATH, classpath);

        classpath = ClassPathLoader.checkClasspathName(EXISTING_FILE_PATH);
        assertEquals(EXISTING_FILE_PATH, classpath);
    }

    @Test
    void shouldHandleExistingFile() {
        final var loader = new ClassPathLoader(EXISTING_CLASSPATH_FILE);
        assertTrue(loader.isReadable());
        assertFalse(loader.isFilesystemLoader());
        assertNotNull(loader.inputStream());
    }

    @Test
    void shouldHandleExistingFileInJar() {
        final var loader = new ClassPathLoader(JAR_LOCATED_CLASSPATH_FILE_NAME);
        assertTrue(loader.isReadable(), "file must be readable: " + JAR_LOCATED_CLASSPATH_FILE_NAME);
        assertNotNull(loader.inputStream(), "input stream must not be null");
    }

    @Test
    void shouldHandleNotExistingFile() {
        final var loader = new ClassPathLoader(NOT_EXISTING_CLASSPATH_FILE);
        assertFalse(loader.isReadable());
    }

    @Test
    void shouldFailToLoadNotExistingFile() {
        var classPathLoader = new ClassPathLoader(NOT_EXISTING_CLASSPATH_FILE);
        assertThrows(IllegalStateException.class, classPathLoader::inputStream);
    }

    @Test
    void shouldFailToComputeCorrectClassPathOnNull() {
        assertThrows(IllegalArgumentException.class, () -> ClassPathLoader.checkClasspathName(null));
    }

    @Test
    void shouldFailToComputeCorrectClassPathOnClasspathPrefix() {
        var prefix = FileTypePrefix.CLASSPATH.getPrefix();
        assertThrows(IllegalArgumentException.class, () -> ClassPathLoader.checkClasspathName(prefix));
    }

    @Test
    void shouldFailToComputeCorrectClassPathOnFilePrefix() {
        assertThrows(IllegalArgumentException.class,
                () -> ClassPathLoader.checkClasspathName(FileTypePrefix.FILE + EXISTING_FILE_PATH));
    }
}
