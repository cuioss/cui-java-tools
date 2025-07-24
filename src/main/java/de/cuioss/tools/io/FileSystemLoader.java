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

import de.cuioss.tools.base.Preconditions;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.string.MoreStrings;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serial;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;

import static de.cuioss.tools.string.MoreStrings.isEmpty;
import static java.util.Objects.requireNonNull;

/**
 * File-system based variant. Responsible for all non
 * {@link FileTypePrefix#CLASSPATH} files.
 *
 * @author Oliver Wolff
 */
@EqualsAndHashCode(of = {"normalizedPathName"})
@ToString
public class FileSystemLoader implements FileReaderWriter {

    @Serial
    private static final long serialVersionUID = -1278929108857440808L;

    private static final CuiLogger LOGGER = new CuiLogger(FileSystemLoader.class);

    private final String normalizedPathName;

    @Getter
    private final boolean readable;

    @Getter
    private final boolean writable;

    @Getter
    private final StructuredFilename fileName;

    /**
     * @param pathName must not be null nor empty, must not start with the prefix
     *                 "classpath:" but may start with the prefix "file:" and
     *                 contain at least one character despite the prefix. On all
     *                 other cases a {@link IllegalArgumentException} will be
     *                 thrown.
     */
    public FileSystemLoader(final String pathName) {
        requireNonNull(pathName);
        normalizedPathName = checkPathName(pathName);
        Preconditions.checkArgument(!isEmpty(normalizedPathName), "'%s' can not be normalized", pathName);
        final var path = getPath();
        readable = MorePaths.checkReadablePath(path, false, true);
        writable = MorePaths.checkAccessiblePath(path, false, false);
        fileName = new StructuredFilename(path.toAbsolutePath().getFileName().toString());
    }

    /**
     * Variant that uses a path as the constructor argument
     *
     * @param path must not be null
     */
    public FileSystemLoader(final Path path) {
        this(requireNonNull(path).toFile().getAbsolutePath());
    }

    /**
     * @return the path
     */
    public Path getPath() {
        return Path.of(normalizedPathName);
    }

    @Override
    public InputStream inputStream() throws IOException {
        Preconditions.checkState(isReadable(), "'%s' is not readable", normalizedPathName);
        return Files.newInputStream(getPath());
    }

    /**
     * Checks and modifies a given pathName
     *
     * @param pathName must not be null nor empty, must not start with the prefix
     *                 "classpath:" but may start with the prefix "file:" and
     *                 contain at least one character despite the prefix. On all
     *                 other cases a {@link IllegalArgumentException} will be
     *                 thrown.
     *
     * @return the normalized pathname without prefix
     */
    public static String checkPathName(final String pathName) {
        MoreStrings.requireNotEmpty(pathName, "pathName");
        if (pathName.startsWith(FileTypePrefix.CLASSPATH.getPrefix())) {
            throw new IllegalArgumentException("Invalid path name, must start not start with "
                    + FileTypePrefix.CLASSPATH + " but was: " + pathName);
        }
        var newPathName = pathName;
        if (pathName.startsWith(FileTypePrefix.FILE.getPrefix())) {
            newPathName = FileTypePrefix.FILE.removePrefix(pathName);
        } else if (pathName.startsWith(FileTypePrefix.EXTERNAL.getPrefix())) {
            try {
                newPathName = new File(".").getCanonicalPath() + FileTypePrefix.EXTERNAL.removePrefix(pathName);
                LOGGER.debug("Loading config file from external path: %s", newPathName);
            } catch (final IOException e) {
                LOGGER.error("Retrieving the current dir failed: ", e);
            }
        }

        if (isEmpty(newPathName)) {
            throw new IllegalArgumentException("Filename " + pathName + " is invalid");
        }
        return MorePaths.getRealPathSafely(newPathName).toString();
    }

    @Override
    public boolean isFilesystemLoader() {
        return true;
    }

    @Override
    public URL getURL() {
        try {
            return getPath().toUri().toURL();
        } catch (final MalformedURLException e) {
            throw new IllegalStateException("Unable to convert path to URL: " + getPath(), e);
        }
    }

    /**
     * Truncate and overwrite an existing file, or create the file if it doesn't
     * initially exist.
     */
    @Override
    public OutputStream outputStream() throws IOException {
        Preconditions.checkState(isWritable(), "'%s' is not writable", normalizedPathName);
        return Files.newOutputStream(getPath());
    }
}
