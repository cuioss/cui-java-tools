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

import de.cuioss.test.generator.Generators;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

import static de.cuioss.tools.io.MorePaths.*;
import static org.junit.jupiter.api.Assertions.*;

class MorePathsTest {

    private static final String NOT_THERE = "not.there";
    private static final String TARGET = "target";
    private static final String POM_XML = "pom.xml";
    private static final String TEST_FILE_NAME = "someTestFile.txt";
    private static final Path TEST_FILE_SOURCE_PATH = Path.of("src/test/resources", TEST_FILE_NAME);

    static final Path POM_PATH = Path.of(POM_XML);
    static final Path NOT_THERE_PATH = Path.of(NOT_THERE);
    private static final SimpleDateFormat FILE_SUFFIX_DATEFORMAT = new SimpleDateFormat("yyyyMMddHHmmss");

    private static final Path BASE_PATH = Path.of("src/test/resources");
    private static final Path TARGET_PATH = Path.of("target/test-classes");
    private static final Path TARGET_PLAYGROUND = TARGET_PATH.resolve("playground");

    private static final Path EXISTING_FILE = Path.of(POM_XML);
    private static final Path NOT_EXISTING_DIRECTORY = Path.of("not/there");

    private Path playGroundBase;
    private Path playGroundBackup;

    @BeforeEach
    void before() throws IOException {
        var playGround = Path.of("target/playground");
        if (!Files.exists(playGround)) {
            Files.createDirectories(playGround);
        }
        var stamp = FILE_SUFFIX_DATEFORMAT.format(new Date()) + Generators.nonEmptyStrings().next();
        playGroundBase = playGround.resolve(stamp);
        Files.createDirectories(playGroundBase);
        playGroundBackup = playGroundBase.resolve(BACKUP_DIR_NAME);
    }

    @AfterEach
    void after() {
        MorePaths.deleteQuietly(playGroundBase.getParent());
    }

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

    @Test
    void shouldCheckExisitingPaths() {
        assertTrue(checkAccessiblePath(BASE_PATH, true, true));
        assertTrue(checkAccessiblePath(BASE_PATH, true, false));
        // File is not directory
        assertFalse(checkAccessiblePath(BASE_PATH, false, true));
        assertFalse(checkAccessiblePath(BASE_PATH, false, false));

        assertFalse(checkAccessiblePath(NOT_EXISTING_DIRECTORY, true, true));
        assertFalse(checkAccessiblePath(NOT_EXISTING_DIRECTORY, true, false));

        // File is not directory
        assertFalse(checkAccessiblePath(EXISTING_FILE, true, true));
        assertFalse(checkAccessiblePath(EXISTING_FILE, true, false));
        assertTrue(checkAccessiblePath(EXISTING_FILE, false, true));
        assertTrue(checkAccessiblePath(EXISTING_FILE, false, false));
        assertTrue(checkAccessiblePath(TARGET_PATH, true, true));
        assertTrue(checkAccessiblePath(TARGET_PATH, true, false));
    }

    @Test
    void shouldCheckExecutablePath() throws IOException {
        assertFalse(checkExecutablePath(BASE_PATH, true));
        assertFalse(checkExecutablePath(BASE_PATH, false));

        assertFalse(checkExecutablePath(NOT_EXISTING_DIRECTORY, true));
        assertFalse(checkExecutablePath(NOT_EXISTING_DIRECTORY, false));

        var testFile = copyTestFileToPlayground();

        testFile.toFile().setExecutable(true);
        assertTrue(checkExecutablePath(testFile, true));
        assertTrue(checkExecutablePath(testFile, false));
    }

    @Test
    void shouldProvideBackupDirectoryIfParentExists() {
        assertFalse(playGroundBackup.toFile().exists(), "File should not exist as a precondition");
        assertTrue(getBackupDirectoryForPath(playGroundBase).toFile().exists());
        // Now the file should not be created but referenced
        assertTrue(getBackupDirectoryForPath(playGroundBase).toFile().exists());
    }

    @Test
    void shouldFailToBackupNonExisitingFile() {
        assertThrows(IllegalArgumentException.class, () ->
                backupFile(TARGET_PLAYGROUND));
    }

    @Test
    void shouldBackupExistingFile() throws IOException {
        var existing = copyPomFileToPlayground();

        assertFalse(Files.exists(playGroundBackup));
        backupFile(existing);
        assertTrue(Files.exists(playGroundBackup));

        final List<Path> children = Files.list(playGroundBackup).toList();
        assertEquals(1, children.size());
        final var fileName = children.getFirst().getFileName().toString();
        assertTrue(fileName.startsWith(POM_XML + BACKUP_FILE_SUFFIX));

        MorePaths.contentEquals(existing, children.getFirst());

    }

    @Test
    void shouldCreateTempFile() throws IOException {
        var existing = copyPomFileToPlayground();

        assertFalse(Files.exists(playGroundBackup));
        var temp = copyToTempLocation(existing);
        assertTrue(Files.exists(temp));

        MorePaths.contentEquals(existing, temp);

    }

    @Test
    void shouldFailToProvideBackupDirectoryIfParentNotExists() {
        assertThrows(IllegalArgumentException.class, () ->
                getBackupDirectoryForPath(NOT_EXISTING_DIRECTORY));
    }

    @Test
    void shouldDetermineFilename() throws IOException {
        final List<Path> children = Files.list(playGroundBase).toList();
        assertTrue(children.isEmpty());
        var filename = "filename";
        var newFilePath = createNonExistingPath(playGroundBase, filename);
        assertFalse(Files.exists(newFilePath));
        assertEquals(filename, newFilePath.getFileName().toString());
        Files.copy(EXISTING_FILE, newFilePath, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.COPY_ATTRIBUTES);
        assertTrue(Files.exists(newFilePath));
        for (var counter = 1; counter < 20; counter++) {
            newFilePath = createNonExistingPath(playGroundBase, filename);
            assertFalse(Files.exists(newFilePath));
            assertEquals(filename + "_" + counter, newFilePath.getFileName().toString());
            Files.copy(EXISTING_FILE, newFilePath, StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.COPY_ATTRIBUTES);
            assertTrue(Files.exists(newFilePath));
        }
        // The next one should fail on create
        try {
            createNonExistingPath(playGroundBase, filename);
            fail("Should have thrown IllegalStateException");
        } catch (IllegalStateException e) {
            assertNotNull(e);
        }
    }

    @Test
    void shouldSaveAndBackup() throws IOException {
        var existingFile = copyPomFileToPlayground();

        saveAndBackup(existingFile, filePath -> assertNotEquals(existingFile.toAbsolutePath().toString(),
                filePath.toAbsolutePath().toString()));
        assertTrue(Files.exists(playGroundBackup));
    }

    private Path copyPomFileToPlayground() throws IOException {
        var existingFile = playGroundBase.resolve(POM_XML);
        Files.copy(EXISTING_FILE, existingFile, StandardCopyOption.REPLACE_EXISTING,
                StandardCopyOption.COPY_ATTRIBUTES);
        assertFalse(Files.exists(playGroundBackup), "File could not be created");
        return existingFile;
    }

    private Path copyTestFileToPlayground() throws IOException {
        var path = playGroundBase.resolve(TEST_FILE_NAME);
        if (path.toFile().exists()) {
            return path;
        }
        Files.copy(TEST_FILE_SOURCE_PATH, path, StandardCopyOption.REPLACE_EXISTING,
                StandardCopyOption.COPY_ATTRIBUTES);
        assertTrue(path.toFile().exists());
        return path;
    }

    @Test
    void deleteQuietlyForNull() {
        assertDoesNotThrow(() -> {
            assertFalse(deleteQuietly(null));
        });
    }

    @Test
    void deleteQuietlyDir() throws IOException {
        var existingFile = copyPomFileToPlayground();

        var testDirectory = playGroundBackup.resolve("directory");
        testDirectory.toFile().mkdirs();

        assertTrue(testDirectory.toFile().exists());
        assertTrue(existingFile.toFile().exists());
        assertTrue(deleteQuietly(playGroundBase));
        assertFalse(testDirectory.toFile().exists());
        assertFalse(existingFile.toFile().exists());
    }

    @Test
    void deleteQuietlyFile() throws IOException {
        var existingFile = copyPomFileToPlayground();

        assertTrue(existingFile.toFile().exists());
        assertTrue(deleteQuietly(playGroundBase));
        assertFalse(existingFile.toFile().exists());

    }

    @Test
    void deleteQuietlyNonExistent() {
        var testFile = playGroundBase.resolve(POM_XML);
        assertFalse(testFile.toFile().exists());

        assertDoesNotThrow(() -> assertFalse(deleteQuietly(testFile)));
    }

    @Test
    void contentEquals() throws Exception {

        // Non-existent files
        var notThere1 = playGroundBase.resolve(POM_XML);
        var notThere2 = playGroundBase.resolve("2" + POM_XML);
        // both don't exist
        assertTrue(MorePaths.contentEquals(notThere1, notThere1));
        assertTrue(MorePaths.contentEquals(notThere1, notThere2));
        assertTrue(MorePaths.contentEquals(notThere2, notThere2));
        assertTrue(MorePaths.contentEquals(notThere2, notThere1));

        // Directories
        try {
            MorePaths.contentEquals(playGroundBase, playGroundBase);
            fail("Comparing directories should fail with an IOException");
        } catch (final IOException ioe) {
            // expected
        }

        // Different files
        var existing1 = copyPomFileToPlayground();
        var existing2 = copyTestFileToPlayground();

        assertFalse(MorePaths.contentEquals(existing1, existing2));
        assertTrue(MorePaths.contentEquals(existing1, POM_PATH));

        assertTrue(MorePaths.contentEquals(existing1, existing1));
        assertTrue(MorePaths.contentEquals(existing2, existing2));

    }

    @Test
    void checkSamePath() {
        assertTrue(MorePaths.isSameFile(EXISTING_FILE, EXISTING_FILE));
        assertTrue(MorePaths.isSameFile(null, null));
        assertFalse(MorePaths.isSameFile(EXISTING_FILE, null));
        assertFalse(MorePaths.isSameFile(null, EXISTING_FILE));
        assertFalse(MorePaths.isSameFile(EXISTING_FILE, NOT_THERE_PATH));
        assertFalse(MorePaths.isSameFile(EXISTING_FILE, NOT_EXISTING_DIRECTORY));
        assertTrue(MorePaths.isSameFile(NOT_THERE_PATH, NOT_THERE_PATH),
                "expected two equal non-existing paths to be the same");
    }
}
