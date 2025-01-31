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

import de.cuioss.tools.logging.CuiLogger;
import lombok.NonNull;
import lombok.experimental.UtilityClass;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.text.SimpleDateFormat;
import java.util.Date;

import static java.util.Objects.requireNonNull;

/**
 * Provides {@link Path} related utilities
 *
 * @author Oliver Wolff
 *
 */
@UtilityClass
public final class MorePaths {

    private static final CuiLogger log = new CuiLogger(MorePaths.class);

    /** ".backup" */
    public static final String BACKUP_DIR_NAME = ".backup";

    /** "File or Directory {} is not accessible, reason: {}". */
    public static final String MSG_DIRECTORY_NOT_ACCESSIBLE = "File or Directory {} is not accessible, reason: {}";

    /** The prefix to be attached to a backup-file */
    public static final String BACKUP_FILE_SUFFIX = ".bck_";

    /**
     * Tries to determine the real-path by calling
     * {@link Path#toRealPath(java.nio.file.LinkOption...)} with no further
     * parameter passed. In case the real path can not be resolved it will LOG at
     * warn-level and return {@link Path#toAbsolutePath()}.
     *
     * @param path must not be null
     * @return the real-path if applicable, {@link Path#toAbsolutePath()} otherwise.
     */
    public static Path getRealPathSafely(Path path) {
        requireNonNull(path, "Path must not be null");
        try {
            return path.toRealPath();
        } catch (IOException e) {
            log.warn("Unable to resolve real path for '{}', due to '{}'. Returning absolutePath.", path, e.getMessage(),
                    e);
            return path.toAbsolutePath();
        }
    }

    /**
     * Tries to determine the real-path, see {@link #getRealPathSafely(Path)} for
     * details and {@link Path#of(String, String...)} for details regarding the
     * parameter
     *
     * @param first the path string or initial part of the path string
     * @param more  additional strings to be joined to form the path string
     * @return the real-path if applicable, {@link Path#toAbsolutePath()} otherwise.
     */
    public static Path getRealPathSafely(String first, String... more) {
        return getRealPathSafely(Path.of(first, more));
    }

    /**
     * Tries to determine the real-path, see {@link #getRealPathSafely(Path)} for
     * details
     *
     * @param file the {@link Path} to be looked up
     *
     * @return the real-path if applicable, {@link Path#toAbsolutePath()} otherwise.
     */
    public static Path getRealPathSafely(File file) {
        requireNonNull(file, "File must not be null");
        return getRealPathSafely(file.toPath());
    }

    /**
     * Checks whether the given {@link Path} denotes an existing read and writable
     * directory or file.
     *
     * @param path              to checked, must not be null
     * @param checkForDirectory check whether it is a file or directory
     * @param verbose           indicates whether to log errors at warn-level
     *
     * @return boolean indicating whether the given {@link Path} denotes an existing
     *         read and writable directory.
     */
    public static boolean checkAccessiblePath(final @NonNull Path path, final boolean checkForDirectory,
            final boolean verbose) {
        if (!checkReadablePath(path, checkForDirectory, verbose)) {
            return false;
        }
        final var pathFile = path.toFile();
        final var absolutePath = pathFile.getAbsolutePath();
        if (!pathFile.canWrite()) {
            if (verbose) {
                log.warn(MSG_DIRECTORY_NOT_ACCESSIBLE, absolutePath, "Not Writable");
            }
            return false;
        }
        log.debug("{} denotes an existing file / directory with read and write permissions", absolutePath);
        return true;
    }

    /**
     * Checks whether the given {@link Path} denotes an existing readable directory
     * or file.
     *
     * @param path              to checked, must not be null
     * @param checkForDirectory check whether it is a file or directory
     * @param verbose           indicates whether to log errors at warn-level
     *
     * @return boolean indicating whether the given {@link Path} denotes an existing
     *         readable directory.
     */
    public static boolean checkReadablePath(final @NonNull Path path, final boolean checkForDirectory,
            final boolean verbose) {
        final var pathFile = path.toFile();
        final var absolutePath = pathFile.getAbsolutePath();
        if (!pathFile.exists()) {
            if (verbose) {
                log.warn(MSG_DIRECTORY_NOT_ACCESSIBLE, absolutePath, "Not Existing");
            }
            return false;
        }
        if (checkForDirectory) {
            if (!pathFile.isDirectory()) {
                if (verbose) {
                    log.warn(MSG_DIRECTORY_NOT_ACCESSIBLE, absolutePath, "Not a directory");
                }
                return false;
            }
        } else if (!pathFile.isFile()) {
            if (verbose) {
                log.warn(MSG_DIRECTORY_NOT_ACCESSIBLE, absolutePath, "Not a file");
            }
            return false;
        }
        if (!pathFile.canRead()) {
            if (verbose) {
                log.warn(MSG_DIRECTORY_NOT_ACCESSIBLE, absolutePath, "Not Readable");
            }
            return false;
        }
        log.debug("{} denotes an existing file / directory with read permissions", absolutePath);
        return true;
    }

    /**
     * Checks whether the given {@link Path} denotes an existing executable file.
     *
     * @param path    to checked, must not be null
     * @param verbose indicates whether to log errors at warn-level
     *
     * @return boolean indicating whether the given {@link Path} denotes an existing
     *         readable directory.
     */
    public static boolean checkExecutablePath(final @NonNull Path path, final boolean verbose) {
        final var pathFile = path.toFile();
        final var absolutePath = pathFile.getAbsolutePath();
        if (!pathFile.exists()) {
            if (verbose) {
                log.warn(MSG_DIRECTORY_NOT_ACCESSIBLE, absolutePath, "Not Existing");
            }
            return false;
        }
        if (!pathFile.isFile()) {
            if (verbose) {
                log.warn(MSG_DIRECTORY_NOT_ACCESSIBLE, absolutePath, "Not a file");
            }
            return false;
        }
        if (!pathFile.canExecute()) {
            if (verbose) {
                log.warn(MSG_DIRECTORY_NOT_ACCESSIBLE, absolutePath, "Not Executable");
            }
            return false;
        }
        log.debug("{} denotes an existing file / directory with execute permission", absolutePath);
        return true;
    }

    /**
     * Creates / or references a backup-directory named ".backup" within the given
     * directory and returns it
     *
     * @param directory must not null and denote an existing writable directory,
     *                  otherwise am {@link IllegalArgumentException} will be
     *                  thrown.
     * @return the ".backup" directory
     */
    public static Path getBackupDirectoryForPath(final Path directory) {
        if (!checkAccessiblePath(directory, true, true)) {
            throw new IllegalArgumentException("Given path '%s' does not denote an existing writable directory"
                    .formatted(directory.toFile().getAbsolutePath()));
        }
        final var backup = directory.resolve(BACKUP_DIR_NAME);
        final var backupAsFile = backup.toFile();
        if (!backupAsFile.exists() && !backupAsFile.mkdir()) {
            throw new IllegalStateException(
                    "Unable to create directory '%s'".formatted(backup.toFile().getAbsolutePath()));
        }
        return backup;

    }

    /**
     * Backups the file, identified by the given path into the backup directory,
     * derived with {@link #getBackupDirectoryForPath(Path)}. The original file
     * attributes will be applied to the copied filed, See
     * {@link StandardCopyOption#COPY_ATTRIBUTES}.
     *
     * @param path must not be null and denote an existing read and writable file
     * @return Path on the newly created file
     * @throws IOException if an I/O error occurs
     */
    public static Path backupFile(final Path path) throws IOException {
        assertAccessibleFile(path);
        var backupDir = getBackupDirectoryForPath(path.getParent());

        var backupFile = createNonExistingPath(backupDir,
                path.getFileName() + BACKUP_FILE_SUFFIX + new SimpleDateFormat("yyyyMMddHHmmss").format(new Date()));

        Files.copy(path, backupFile, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.COPY_ATTRIBUTES);
        log.debug("Created backup from '{}' at '{}'", path.toFile().getAbsolutePath(),
                backupFile.toFile().getAbsolutePath());
        return backupFile;
    }

    /**
     * Creates a temp-copy of the given file, identified by the given path. The
     * original file attributes will be applied to the copied filed, See
     * {@link StandardCopyOption#COPY_ATTRIBUTES}.
     * <h2>Caution: Security-Impact</h2> Creating a temp-file might introduce a
     * security issue. Never ever use this location for sensitive information that
     * might be of interest for an attacker
     *
     * @param path must not be null and denote an existing read and writable file
     * @return Path on the newly created file
     * @throws IOException if an I/O error occurs
     */
    @SuppressWarnings("java:S5443") // owolff: See hint Caution: Security-Impact
    public static Path copyToTempLocation(final Path path) throws IOException {
        assertAccessibleFile(path);
        var filename = new StructuredFilename(path.getFileName());
        var tempFile = Files.createTempFile(filename.getNamePart(), filename.getSuffix());

        Files.copy(path, tempFile, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.COPY_ATTRIBUTES);
        log.debug("Created temp-file from '{}' at '{}'", path.toFile().getAbsolutePath(),
                tempFile.toFile().getAbsolutePath());
        return tempFile;
    }

    /**
     * Asserts whether a given {@link Path} is accessible, saying it exits as a file
     * and is read and writable. If not it will throw an
     * {@link IllegalArgumentException}
     *
     * @param path to be checked, must not be null
     */
    public static void assertAccessibleFile(final Path path) {
        requireNonNull(path, "path");
        if (!checkAccessiblePath(path, false, true)) {
            throw new IllegalArgumentException("Given path '%s' does not denote an existing readable file"
                    .formatted(path.toFile().getAbsolutePath()));
        }
    }

    static Path createNonExistingPath(final Path parentDir, final String fileName) {
        var backupFile = parentDir.resolve(fileName);
        if (!backupFile.toFile().exists()) {
            return backupFile;
        }

        for (var counter = 1; counter < 20; counter++) {
            var newName = fileName + "_" + counter;
            var newBackupFile = parentDir.resolve(newName);
            if (!newBackupFile.toFile().exists()) {
                return newBackupFile;
            }
        }
        throw new IllegalStateException("Unable to determine a non-existing file within '%s' for file-name '%s'"
                .formatted(parentDir.toFile().getAbsolutePath(), fileName));
    }

    /**
     * Deletes a file, never throwing an exception. If file is a directory, delete
     * it and all subdirectories. Inspired by
     * org.apache.commons.io.FileUtils#deleteQuietly
     * <p>
     * The difference between File.delete() and this method are:
     * <ul>
     * <li>A directory to be deleted does not have to be empty.</li>
     * <li>No exceptions are thrown when a file or directory cannot be deleted.</li>
     * </ul>
     *
     * @param path file or directory to delete, can be {@code null}
     * @return {@code true} if the file or directory was deleted, otherwise
     *         {@code false}
     */
    public static boolean deleteQuietly(final Path path) {
        log.trace("Deleting file {}", path);
        if (path == null) {
            return false;
        }
        var file = path.toFile();
        final var absolutePath = file.getAbsolutePath();
        if (!file.exists()) {
            log.trace("Path {} does not exist", absolutePath);
            return false;
        }
        var recursiveSucceful = true;
        try {
            if (file.isDirectory()) {
                log.trace("Path {} is directory, checking children", absolutePath);
                for (String child : file.list()) {
                    if (!deleteQuietly(path.resolve(child))) {
                        recursiveSucceful = false;
                    }

                }
            }
        } catch (final Exception e) {
            log.trace(e, "Unable to check Path {} whether it is a directory", absolutePath);
        }

        try {
            if (Files.deleteIfExists(path)) {
                log.trace("Successully deleted path {}", absolutePath);
            } else {
                recursiveSucceful = false;
            }
        } catch (final Exception e) {
            log.trace(e, "Unable to delete Path {}", absolutePath);
            return false;
        }
        return recursiveSucceful;
    }

    /**
     *
     * Compares the contents of two files to determine if they are equal or not.
     * <p>
     * This method checks to see if the two files are different lengths or if they
     * point to the same file, before resorting to byte-by-byte comparison of the
     * contents.
     * <p>
     * Taken from org.apache.commons.io.FileUtils.contentEquals(File, File) Code
     * origin: Avalon
     *
     * @param path1 the first file
     * @param path2 the second file
     * @return true if the content of the files are equal or they both don't exist,
     *         false otherwise
     * @throws IOException in case of an I/O error
     */
    public static boolean contentEquals(final Path path1, final Path path2) throws IOException {
        requireNonNull(path1);
        requireNonNull(path2);
        var file1 = path1.toFile();
        var file2 = path2.toFile();
        final var file1Exists = file1.exists();
        if (file1Exists != file2.exists()) {
            return false;
        }

        if (!file1Exists) {
            // two not existing files are equal
            return true;
        }

        if (file1.isDirectory() || file2.isDirectory()) {
            // don't want to compare directory contents
            throw new IOException("Can't compare directories, only files");
        }

        if (file1.length() != file2.length()) {
            // lengths differ, cannot be equal
            return false;
        }

        if (file1.getCanonicalFile().equals(file2.getCanonicalFile())) {
            // same file
            return true;
        }

        try (InputStream input1 = new FileInputStream(file1); InputStream input2 = new FileInputStream(file2)) {
            return IOStreams.contentEquals(input1, input2);
        }
    }

    /**
     * Command pattern interface delegating the file write operation to its caller.
     *
     * @author Sven Haag
     *
     */
    public interface FileWriteHandler {

        /**
         * @param filePath where the write operation should take place on.
         * @throws IOException if an I/O error occurs
         */
        void write(final Path filePath) throws IOException;
    }

    /**
     * Save a file by maintaining all its attributes and permissions. Also creates a
     * backup, see {@linkplain #backupFile(Path)}.
     *
     * <h1>Usage</h1>
     * <p>
     * PathUtils.saveAndBackup(myOriginalFilePath, targetPath ->
     * JdomHelper.writeJdomToFile(document, targetPath));
     * </p>
     *
     * @param filePath         path to the original / target file
     * @param fileWriteHandler do your write operation to the given file path
     *                         provided by
     *                         {@linkplain FileWriteHandler#write(Path)}.
     * @throws IOException if an I/O error occurs
     */
    public static void saveAndBackup(final Path filePath, final FileWriteHandler fileWriteHandler) throws IOException {
        // Copy original file to temp
        final var temp = copyToTempLocation(filePath);

        // Save data to temp file
        fileWriteHandler.write(temp);

        // Create backup from original
        backupFile(filePath);

        // Replace original with temp file
        java.nio.file.Files.copy(temp, filePath, StandardCopyOption.REPLACE_EXISTING,
                StandardCopyOption.COPY_ATTRIBUTES);
    }

    /**
     * Checks, if the two given paths are pointing to the same location.
     * <p>
     * If both paths are not {@code null} and do {@link File#exists()}, the
     * {@link Files#isSameFile(Path, Path)} method is used to check if both paths
     * are pointing to the same location. Otherwise, if one of the paths does not
     * exist, the {@link Paths#equals(Object)} method is used.
     *
     * @param path  to be compared with path2
     * @param path2 to be compared with path
     *
     * @return {@code true}, if both paths are {@code null}. {@code true}, if both
     *         paths not {@code null}, do exist, and
     *         {@link Files#isSameFile(Path, Path)}. {@code true}, if both paths not
     *         {@code null} and {@link Paths#equals(Object)} {@code false}
     *         otherwise.
     */
    public static boolean isSameFile(Path path, Path path2) {
        if (null == path && null == path2) {
            return true;
        }

        if (null != path && null != path2) {
            if (!path.toFile().exists() || !path2.toFile().exists()) {
                log.debug("""
                        Comparing paths with #equals, as at least one path does not exist. \
                        path_a={}, path_b={}\
                        """, path, path2);
                return path.equals(path2);
            }
            try {
                return Files.isSameFile(path, path2);
            } catch (final IOException e) {
                log.error(e, "Portal-123: Unable to compare path_a={} and path_b={}", path, path2);
            }
        } else {
            log.trace("at least one path is null: path_a={}, path_b={}", path, path2);
        }

        return false;
    }
}
