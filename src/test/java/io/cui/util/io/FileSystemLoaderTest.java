package io.cui.util.io;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;

import org.junit.jupiter.api.Test;

@SuppressWarnings("resource")
class FileSystemLoaderTest {

    private static final String EXISTING_FILE = "pom.xml";

    private static final String EXISTING_EXTERNAL_FILE = "external:/pom.xml";

    private static final String NOT_EXISTING_FILE = "notThere.txt";

    private static final String EXISTING_DIRECTORY = "src";

    private static final String EXISTING_EXTERNAL_DIRECTORY = "external:/src";

    private static final String EXISTING_FILE_PATH = Paths.get(EXISTING_FILE).toAbsolutePath()
            .toString();

    private static final String EXISTING_DIRECTORY_PATH = Paths.get(EXISTING_DIRECTORY)
            .toAbsolutePath().toString();

    private static final String NOT_EXISTING_FILE_PATH = Paths.get(NOT_EXISTING_FILE)
            .toAbsolutePath().toString();

    @Test
    void shouldHandleExistingFile() throws IOException {
        final FileSystemLoader loader = new FileSystemLoader(EXISTING_FILE_PATH);
        assertTrue(loader.isReadable());
        assertTrue(loader.isFilesystemLoader());
        assertEquals(EXISTING_FILE, loader.getFileName().getOriginalName());
        assertNotNull(loader.inputStream());
    }

    @Test
    void shouldHandlePathAsArgument() throws IOException {
        final FileSystemLoader loader = new FileSystemLoader(Paths.get(EXISTING_FILE_PATH));
        assertTrue(loader.isReadable());
        assertTrue(loader.isFilesystemLoader());
        assertEquals(EXISTING_FILE, loader.getFileName().getOriginalName());
        assertNotNull(loader.inputStream());
    }

    @Test
    void shouldHandleExistingExternalFile() throws IOException {
        final FileSystemLoader loader = new FileSystemLoader(EXISTING_EXTERNAL_FILE);
        assertTrue(loader.isReadable());
        assertTrue(loader.isFilesystemLoader());
        assertEquals(EXISTING_FILE, loader.getFileName().getOriginalName());
        assertNotNull(loader.inputStream());
    }

    @Test
    void shouldHandleExistingDirectory() {
        final FileSystemLoader loader = new FileSystemLoader(EXISTING_DIRECTORY_PATH);
        assertFalse(loader.isReadable());
        assertEquals(EXISTING_DIRECTORY, loader.getFileName().getOriginalName());
    }

    @Test
    void shouldHandleExistingExternalDirectory() {
        final FileSystemLoader loader = new FileSystemLoader(EXISTING_EXTERNAL_DIRECTORY);
        assertFalse(loader.isReadable());
        assertEquals(EXISTING_DIRECTORY, loader.getFileName().getOriginalName());
    }

    @Test
    void shouldHandleNotExistingFile() {
        final FileSystemLoader loader = new FileSystemLoader(NOT_EXISTING_FILE_PATH);
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
        String prefix = FileTypePrefix.FILE.getPrefix();
        assertThrows(IllegalArgumentException.class,
                () -> {
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
        FileSystemLoader fileSystemLoader = new FileSystemLoader(NOT_EXISTING_FILE_PATH);
        assertThrows(IllegalStateException.class, () -> {
            fileSystemLoader.inputStream();
        });
    }
}
