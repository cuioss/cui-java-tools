package io.cui.util.io;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.nio.file.Paths;

import org.junit.jupiter.api.Test;

import io.cui.util.support.ObjectMethodsAsserts;

class StructuredFilenameTest {

    static final String EXISTING_FILE_NAME = "/META-INF/someTestFile.txt";
    static final String SOME_TEST_FILE_TXT = "someTestFile.txt";

    @Test
    void testValidFilename() {
        final StructuredFilename filename = new StructuredFilename("test.suffix");
        assertEquals("test", filename.getNamePart());
        assertEquals("suffix", filename.getSuffix());
    }

    @Test
    void testNoSuffixFilename() {
        final StructuredFilename filename = new StructuredFilename("test");
        assertEquals("test", filename.getNamePart());
        assertNull(filename.getSuffix());
    }

    @Test
    void testMultipleDotsFilename() {
        final StructuredFilename filename = new StructuredFilename("test.dots.suffix");
        assertEquals("test.dots", filename.getNamePart());
        assertEquals("suffix", filename.getSuffix());
    }

    @Test
    void testGetAppendedName() {
        final StructuredFilename filename = new StructuredFilename("test.suffix");
        assertEquals("test-appended.suffix",
                filename.getAppendedName("-appended"));
    }

    @Test
    void shouldHandleDotOnlyName() {
        final StructuredFilename filename = new StructuredFilename(".");
        assertEquals(".", filename.getNamePart());
        assertNull(filename.getSuffix());
    }

    @Test
    void shouldResolvePath() {
        final StructuredFilename filename = new StructuredFilename(Paths.get(EXISTING_FILE_NAME));
        assertEquals(SOME_TEST_FILE_TXT, filename.getOriginalName());
    }

    @Test
    void shouldResolveFile() {
        final StructuredFilename filename =
            new StructuredFilename(Paths.get(EXISTING_FILE_NAME).toFile());
        assertEquals(SOME_TEST_FILE_TXT, filename.getOriginalName());
    }

    @Test
    void shouldImplementObjectContracts() {
        ObjectMethodsAsserts.assertNiceObject(new StructuredFilename("test.suffix"));
    }
}
