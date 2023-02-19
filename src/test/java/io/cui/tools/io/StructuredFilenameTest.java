package io.cui.tools.io;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.nio.file.Paths;

import org.junit.jupiter.api.Test;

import io.cui.tools.support.ObjectMethodsAsserts;

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
        assertEquals("test-appended.suffix",
                filename.getAppendedName("-appended"));
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
        final var filename =
            new StructuredFilename(Paths.get(EXISTING_FILE_NAME).toFile());
        assertEquals(SOME_TEST_FILE_TXT, filename.getOriginalName());
    }

    @Test
    void shouldImplementObjectContracts() {
        ObjectMethodsAsserts.assertNiceObject(new StructuredFilename("test.suffix"));
    }
}
