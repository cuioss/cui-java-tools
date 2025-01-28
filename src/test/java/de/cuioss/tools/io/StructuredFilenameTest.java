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
import static org.junit.jupiter.api.Assertions.assertNull;

import de.cuioss.tools.support.ObjectMethodsAsserts;
import org.junit.jupiter.api.Test;

import java.nio.file.Paths;

class StructuredFilenameTest {

    static final String EXISTING_FILE_NAME = "/META-INF/someTestFile.txt";
    static final String SOME_TEST_FILE_TXT = "someTestFile.txt";

    @Test
    void testValidFilename() {
        final var filename = new StructuredFilename("test.suffix");
        assertEquals("test", filename.getNamePart());
        assertEquals("suffix", filename.getSuffix());
    }

    @Test
    void testNoSuffixFilename() {
        final var filename = new StructuredFilename("test");
        assertEquals("test", filename.getNamePart());
        assertNull(filename.getSuffix());
    }

    @Test
    void testMultipleDotsFilename() {
        final var filename = new StructuredFilename("test.dots.suffix");
        assertEquals("test.dots", filename.getNamePart());
        assertEquals("suffix", filename.getSuffix());
    }

    @Test
    void testGetAppendedName() {
        final var filename = new StructuredFilename("test.suffix");
        assertEquals("test-appended.suffix", filename.getAppendedName("-appended"));
    }

    @Test
    void shouldHandleDotOnlyName() {
        final var filename = new StructuredFilename(".");
        assertEquals(".", filename.getNamePart());
        assertNull(filename.getSuffix());
    }

    @Test
    void shouldResolvePath() {
        final var filename = new StructuredFilename(Paths.get(EXISTING_FILE_NAME));
        assertEquals(SOME_TEST_FILE_TXT, filename.getOriginalName());
    }

    @Test
    void shouldResolveFile() {
        final var filename = new StructuredFilename(Paths.get(EXISTING_FILE_NAME).toFile());
        assertEquals(SOME_TEST_FILE_TXT, filename.getOriginalName());
    }

    @Test
    void shouldImplementObjectContracts() {
        ObjectMethodsAsserts.assertNiceObject(new StructuredFilename("test.suffix"));
    }
}
