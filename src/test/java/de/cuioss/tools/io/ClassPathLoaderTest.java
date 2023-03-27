package de.cuioss.tools.io;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

@SuppressWarnings("resource")
class ClassPathLoaderTest {

    private static final String EXISTING_FILE_PATH = "/META-INF/someTestFile.txt";

    private static final String EXISTING_FILE_PATH_WO_SLASH = "META-INF/someTestFile.txt";

    private static final String EXISTING_CLASSPATH_FILE = FileTypePrefix.CLASSPATH + EXISTING_FILE_PATH;

    private static final String EXISTING_CLASSPATH_FILE_WO_SLASH = FileTypePrefix.CLASSPATH + EXISTING_FILE_PATH_WO_SLASH;

    private static final String JAR_LOCATED_CLASSPATH_FILE_NAME = FileTypePrefix.CLASSPATH + EXISTING_FILE_PATH_WO_SLASH;

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
        assertThrows(IllegalStateException.class,
                () -> classPathLoader.inputStream());
    }

    @Test
    void shouldFailToComputeCorrectClassPathOnNull() {
        assertThrows(IllegalArgumentException.class, () -> ClassPathLoader.checkClasspathName(null));
    }

    @Test
    void shouldFailToComputeCorrectClassPathOnClasspathPrefix() {
        var prefix = FileTypePrefix.CLASSPATH.getPrefix();
        assertThrows(IllegalArgumentException.class,
                () -> ClassPathLoader.checkClasspathName(prefix));
    }

    @Test
    void shouldFailToComputeCorrectClassPathOnFilePrefix() {
        assertThrows(IllegalArgumentException.class,
                () -> ClassPathLoader.checkClasspathName(FileTypePrefix.FILE + EXISTING_FILE_PATH));
    }
}
