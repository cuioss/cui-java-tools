package io.cui.tools.io;

import static io.cui.tools.io.FileLoaderUtility.copyFileToTemp;
import static io.cui.tools.io.FileLoaderUtility.getLoaderForPath;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;

import org.junit.jupiter.api.Test;

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
        assertEquals(getLoaderForPath(FileTypePrefix.CLASSPATH + EXISTING_FILE_NAME).getClass(),
                ClassPathLoader.class);
        assertEquals(
                getLoaderForPath(FileTypePrefix.FILE + EXISTING_FILE_NAME).getClass(),
                FileSystemLoader.class);
        assertEquals(getLoaderForPath(EXISTING_FILE_NAME).getClass(), FileSystemLoader.class);
        assertEquals(getLoaderForPath(NOT_EXISTING_FILE).getClass(), FileSystemLoader.class);
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
