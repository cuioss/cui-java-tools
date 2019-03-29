package de.icw.util.io;

import static de.icw.util.io.MorePaths.BACKUP_DIR_NAME;
import static de.icw.util.io.MorePaths.BACKUP_FILE_SUFFIX;
import static de.icw.util.io.MorePaths.backupFile;
import static de.icw.util.io.MorePaths.checkAccessiblePath;
import static de.icw.util.io.MorePaths.copyToTempLocation;
import static de.icw.util.io.MorePaths.createNonExistingPath;
import static de.icw.util.io.MorePaths.deleteQuietly;
import static de.icw.util.io.MorePaths.getBackupDirectoryForPath;
import static de.icw.util.io.MorePaths.getRealPathSafely;
import static de.icw.util.io.MorePaths.saveAndBackup;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import de.icw.util.support.Generators;

class MorePathsTest {

    private static final String NOT_THERE = "not.there";
    private static final String TARGET = "target";
    private static final String POM_XML = "pom.xml";

    static final Path POM_PATH = Paths.get(POM_XML);
    static final Path NOT_THERE_PATH = Paths.get(NOT_THERE);
    private static final SimpleDateFormat FILE_SUFFIX_DATEFORMAT = new SimpleDateFormat("yyyyMMddHHmmss");

    private static final Path BASE_PATH = Paths.get("src/test/resources");
    private static final Path TARGET_PATH = Paths.get("target/test-classes");
    private static final Path TARGET_PLAYGROUND = TARGET_PATH.resolve("playground");

    private static final Path EXISITING_FILE = Paths.get(POM_XML);
    private static final Path NOT_EXISITING_DIRECTORY = Paths.get("not/there");

    private Path playGroundBase;
    private Path playGroundBackup;

    @BeforeEach
    void before() throws IOException {
        Path playGround = Paths.get("target/playground");
        if (!Files.exists(playGround)) {
            Files.createDirectories(playGround);
        }
        String stamp = FILE_SUFFIX_DATEFORMAT.format(new Date()) + Generators.randomString();
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

        assertFalse(checkAccessiblePath(NOT_EXISITING_DIRECTORY, true, true));
        assertFalse(checkAccessiblePath(NOT_EXISITING_DIRECTORY, true, false));

        // File is not directory
        assertFalse(checkAccessiblePath(EXISITING_FILE, true, true));
        assertFalse(checkAccessiblePath(EXISITING_FILE, true, false));
        assertTrue(checkAccessiblePath(EXISITING_FILE, false, true));
        assertTrue(checkAccessiblePath(EXISITING_FILE, false, false));
        assertTrue(checkAccessiblePath(TARGET_PATH, true, true));
        assertTrue(checkAccessiblePath(TARGET_PATH, true, false));
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
        assertThrows(IllegalArgumentException.class, () -> {
            backupFile(TARGET_PLAYGROUND);
        });
    }

    @Test
    void shouldBackupExisitingFile() throws IOException {
        Path exisiting = createTestPath();

        assertFalse(Files.exists(playGroundBackup));
        backupFile(exisiting);
        assertTrue(Files.exists(playGroundBackup));

        final List<Path> children = Files.list(playGroundBackup).collect(Collectors.toList());
        assertEquals(1, children.size());
        final String fileName = children.iterator().next().getFileName().toString();
        assertTrue(fileName.startsWith(POM_XML + BACKUP_FILE_SUFFIX));

        MorePaths.contentEquals(exisiting, children.get(0));

    }

    @Test
    void shouldCreateTempFile() throws IOException {
        Path exisiting = createTestPath();

        assertFalse(Files.exists(playGroundBackup));
        Path temp = copyToTempLocation(exisiting);
        assertTrue(Files.exists(temp));

        MorePaths.contentEquals(exisiting, temp);

    }

    @Test
    void shouldFailToProvideBackupDirectoryIfParentNotExists() {
        assertThrows(IllegalArgumentException.class, () -> {
            getBackupDirectoryForPath(NOT_EXISITING_DIRECTORY);
        });
    }

    @Test
    void shouldDetermineFilename() throws IOException {
        final List<Path> children = Files.list(playGroundBase).collect(Collectors.toList());
        assertTrue(children.isEmpty());
        String filename = "filename";
        Path newFilePath = createNonExistingPath(playGroundBase, filename);
        assertFalse(Files.exists(newFilePath));
        assertEquals(filename, newFilePath.getFileName().toString());
        Files.copy(EXISITING_FILE, newFilePath, StandardCopyOption.REPLACE_EXISTING,
                StandardCopyOption.COPY_ATTRIBUTES);
        assertTrue(Files.exists(newFilePath));
        for (int counter = 1; counter < 20; counter++) {
            newFilePath = createNonExistingPath(playGroundBase, filename);
            assertFalse(Files.exists(newFilePath));
            assertEquals(filename + "_" + counter, newFilePath.getFileName().toString());
            Files.copy(EXISITING_FILE, newFilePath, StandardCopyOption.REPLACE_EXISTING,
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
    @Disabled // Understand why it is not possible to set the permission to setReadable(false
    void shouldDetectNotReadableDirectory() {
        Path notReadableDirectory = TARGET_PLAYGROUND.resolve("notReadable");
        final File file = notReadableDirectory.toFile().getAbsoluteFile();
        file.mkdirs();
        assertTrue(file.isDirectory());
        assertTrue(file.setReadable(false, false));
        assertFalse(file.canRead());
        assertFalse(checkAccessiblePath(notReadableDirectory, true, true));
        assertFalse(checkAccessiblePath(notReadableDirectory, true, false));
    }

    @Test
    @Disabled // Understand why it is not possible to set the permission to setWritable(false
    void shouldDetectNotWriteableDirectory() {

        Path notWritableDirectory = TARGET_PLAYGROUND.resolve("notWriteable");
        final File file = notWritableDirectory.toFile();
        file.mkdirs();
        assertTrue(file.setWritable(false, false));
        assertFalse(checkAccessiblePath(notWritableDirectory, true, true));
        assertFalse(checkAccessiblePath(notWritableDirectory, true, false));
    }

    @Test
    void shouldSaveAndBackup() throws IOException {
        Path existingFile = createTestPath();

        saveAndBackup(existingFile,
                filePath -> assertNotEquals(existingFile.toAbsolutePath().toString(),
                        filePath.toAbsolutePath().toString()));
        assertTrue(Files.exists(playGroundBackup));
    }

    private Path createTestPath() throws IOException {
        Path existingFile = playGroundBase.resolve(POM_XML);
        Files.copy(EXISITING_FILE, existingFile, StandardCopyOption.REPLACE_EXISTING,
                StandardCopyOption.COPY_ATTRIBUTES);
        assertTrue(!Files.exists(playGroundBackup), "File could not be created");
        return existingFile;
    }

    @Test
    void testDeleteQuietlyForNull() {
        try {
            assertFalse(deleteQuietly(null));
        } catch (final Exception ex) {
            fail(ex.getMessage());
        }
    }

    @Test
    void testDeleteQuietlyDir() throws IOException {

        Path existingFile = createTestPath();

        Path testDirectory = playGroundBackup.resolve("directory");
        testDirectory.toFile().mkdirs();

        assertTrue(testDirectory.toFile().exists());
        assertTrue(existingFile.toFile().exists());
        assertTrue(deleteQuietly(playGroundBase));
        assertFalse(testDirectory.toFile().exists());
        assertFalse(existingFile.toFile().exists());
    }

    @Test
    void testDeleteQuietlyFile() throws IOException {
        Path existingFile = createTestPath();

        assertTrue(existingFile.toFile().exists());
        assertTrue(deleteQuietly(playGroundBase));
        assertFalse(existingFile.toFile().exists());

    }

    @Test
    void testDeleteQuietlyNonExistent() {
        Path testFile = playGroundBase.resolve(POM_XML);
        assertFalse(testFile.toFile().exists());

        try {
            assertFalse(deleteQuietly(testFile));
        } catch (final Exception ex) {
            fail(ex.getMessage());
        }
    }

    @Test
    void testContentEquals() throws Exception {

        // Path file = createTestPath();
        // Path file2 = playGroundBase.resolve("2" + POM_XML);
        // Files.copy(EXISITING_FILE, file2, StandardCopyOption.REPLACE_EXISTING,
        // StandardCopyOption.COPY_ATTRIBUTES);
        // assertTrue(!Files.exists(file2), "File could not be created");

        // Non-existent files
        Path file = playGroundBase.resolve(POM_XML);
        Path file2 = playGroundBase.resolve("2" + POM_XML);
        // both don't exist
        assertTrue(MorePaths.contentEquals(file, file));
        assertTrue(MorePaths.contentEquals(file, file2));
        assertTrue(MorePaths.contentEquals(file2, file2));
        assertTrue(MorePaths.contentEquals(file2, file));

        // Directories
        try {
            MorePaths.contentEquals(playGroundBase, playGroundBase);
            fail("Comparing directories should fail with an IOException");
        } catch (final IOException ioe) {
            // expected
        }

        // Different files
        // final File objFile1 =
        // new File(getTestDirectory(), getName() + ".object");
        // objFile1.deleteOnExit();
        // FileUtils.copyURLToFile(
        // getClass().getResource("/java/lang/Object.class"),
        // objFile1);
        //
        // final File objFile1b =
        // new File(getTestDirectory(), getName() + ".object2");
        // objFile1.deleteOnExit();
        // FileUtils.copyURLToFile(
        // getClass().getResource("/java/lang/Object.class"),
        // objFile1b);
        //
        // final File objFile2 =
        // new File(getTestDirectory(), getName() + ".collection");
        // objFile2.deleteOnExit();
        // FileUtils.copyURLToFile(
        // getClass().getResource("/java/util/Collection.class"),
        // objFile2);
        //
        // assertFalse(contentEquals(objFile1, objFile2));
        // assertFalse(contentEquals(objFile1b, objFile2));
        // assertTrue(contentEquals(objFile1, objFile1b));
        //
        // assertTrue(contentEquals(objFile1, objFile1));
        // assertTrue(contentEquals(objFile1b, objFile1b));
        // assertTrue(contentEquals(objFile2, objFile2));
        //
        // // Equal files
        // file.createNewFile();
        // file2.createNewFile();
        // assertTrue(contentEquals(file, file));
        // assertTrue(contentEquals(file, file2));
    }

    @Test
    void testContentEqualsIgnoreEOL() throws Exception {
        // // Non-existent files
        // final File file1 = new File(getTestDirectory(), getName());
        // final File file2 = new File(getTestDirectory(), getName() + "2");
        // // both don't exist
        // assertTrue(FileUtils.contentEqualsIgnoreEOL(file1, file1, null));
        // assertTrue(FileUtils.contentEqualsIgnoreEOL(file1, file2, null));
        // assertTrue(FileUtils.contentEqualsIgnoreEOL(file2, file2, null));
        // assertTrue(FileUtils.contentEqualsIgnoreEOL(file2, file1, null));
        //
        // // Directories
        // try {
        // FileUtils.contentEqualsIgnoreEOL(getTestDirectory(), getTestDirectory(), null);
        // fail("Comparing directories should fail with an IOException");
        // } catch (final IOException ioe) {
        // // expected
        // }
        //
        // // Different files
        // final File tfile1 = new File(getTestDirectory(), getName() + ".txt1");
        // tfile1.deleteOnExit();
        // FileUtils.write(tfile1, "123\r");
        //
        // final File tfile2 = new File(getTestDirectory(), getName() + ".txt2");
        // tfile1.deleteOnExit();
        // FileUtils.write(tfile2, "123\n");
        //
        // final File tfile3 = new File(getTestDirectory(), getName() + ".collection");
        // tfile3.deleteOnExit();
        // FileUtils.write(tfile3, "123\r\n2");
        //
        // assertTrue(FileUtils.contentEqualsIgnoreEOL(tfile1, tfile1, null));
        // assertTrue(FileUtils.contentEqualsIgnoreEOL(tfile2, tfile2, null));
        // assertTrue(FileUtils.contentEqualsIgnoreEOL(tfile3, tfile3, null));
        //
        // assertTrue(FileUtils.contentEqualsIgnoreEOL(tfile1, tfile2, null));
        // assertFalse(FileUtils.contentEqualsIgnoreEOL(tfile1, tfile3, null));
        // assertFalse(FileUtils.contentEqualsIgnoreEOL(tfile2, tfile3, null));
        //
        // final URL urlCR = getClass().getResource("FileUtilsTestDataCR.dat");
        // assertNotNull(urlCR);
        // final File cr = new File(urlCR.toURI());
        // assertTrue(cr.exists());
        //
        // final URL urlCRLF = getClass().getResource("FileUtilsTestDataCRLF.dat");
        // assertNotNull(urlCRLF);
        // final File crlf = new File(urlCRLF.toURI());
        // assertTrue(crlf.exists());
        //
        // final URL urlLF = getClass().getResource("FileUtilsTestDataLF.dat");
        // assertNotNull(urlLF);
        // final File lf = new File(urlLF.toURI());
        // assertTrue(lf.exists());
        //
        // assertTrue(FileUtils.contentEqualsIgnoreEOL(cr, cr, null));
        // assertTrue(FileUtils.contentEqualsIgnoreEOL(crlf, crlf, null));
        // assertTrue(FileUtils.contentEqualsIgnoreEOL(lf, lf, null));
        //
        // assertTrue(FileUtils.contentEqualsIgnoreEOL(cr, crlf, null));
        // assertTrue(FileUtils.contentEqualsIgnoreEOL(cr, lf, null));
        // assertTrue(FileUtils.contentEqualsIgnoreEOL(crlf, lf, null));
        //
        // // Check the files behave OK when EOL is not ignored
        // assertTrue(contentEquals(cr, cr));
        // assertTrue(contentEquals(crlf, crlf));
        // assertTrue(contentEquals(lf, lf));
        //
        // assertFalse(contentEquals(cr, crlf));
        // assertFalse(contentEquals(cr, lf));
        // assertFalse(contentEquals(crlf, lf));
        //
        // // Equal files
        // file1.createNewFile();
        // file2.createNewFile();
        // assertTrue(FileUtils.contentEqualsIgnoreEOL(file1, file1, null));
        // assertTrue(FileUtils.contentEqualsIgnoreEOL(file1, file2, null));
    }
}
