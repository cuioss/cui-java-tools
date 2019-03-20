package de.icw.util.io;

import static de.icw.util.io.MorePaths.getRealPathSafely;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.jupiter.api.Test;

class MorePathsTest {

    private static final String NOT_THERE = "not.there";
    private static final String TARGET = "target";
    private static final String POM_XML = "pom.xml";

    static final Path POM_PATH = Paths.get(POM_XML);
    static final Path TARGET_PATH = Paths.get(TARGET);
    static final Path NOT_THERE_PATH = Paths.get(NOT_THERE);

    @Test
    void shouldProvideRealPath() {
        assertNotNull(getRealPathSafely(POM_PATH));
        assertNotNull(getRealPathSafely(TARGET_PATH));
        assertNotNull(NOT_THERE_PATH);
    }

    @Test
    void shouldProvideRealPathFromString() {
        assertNotNull(getRealPathSafely(POM_XML));
        assertNotNull(getRealPathSafely(TARGET));
        assertNotNull(TARGET, NOT_THERE);
    }

    @Test
    void shouldProvideRealPathFromFile() {
        assertNotNull(getRealPathSafely(POM_PATH.toFile()));
        assertNotNull(getRealPathSafely(TARGET_PATH.toFile()));
        assertNotNull(NOT_THERE_PATH.toFile());
    }

}
