package de.cuioss.tools.io;

import static de.cuioss.tools.string.MoreStrings.isEmpty;
import static java.util.Objects.requireNonNull;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import de.cuioss.tools.base.Preconditions;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.string.MoreStrings;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;

/**
 * File-system based variant. Responsible for all non {@link FileTypePrefix#CLASSPATH} files.
 *
 * @author Oliver Wolff
 */
@EqualsAndHashCode(of = { "normalizedPathName" })
@ToString
public class FileSystemLoader implements FileReaderWriter {

    private static final long serialVersionUID = -1278929108857440808L;

    private static final CuiLogger LOG = new CuiLogger(FileSystemLoader.class);

    private final String normalizedPathName;

    @Getter
    private final boolean readable;

    @Getter
    private final boolean writable;

    @Getter
    private final StructuredFilename fileName;

    /**
     * @param pathName must not be null nor empty, must not start with the prefix
     *            "classpath:" but may start with the prefix
     *            "file:" and contain at least one character despite the prefix. On all other cases
     *            a {@link IllegalArgumentException} will be
     *            thrown.
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
        return Paths.get(normalizedPathName);
    }

    @Override
    public InputStream inputStream() throws IOException {
        if (!isReadable()) {
            throw new IllegalStateException("'" + normalizedPathName + "' is not readable");
        }
        return Files.newInputStream(getPath());
    }

    /**
     * Checks and modifies a given pathName
     *
     * @param pathName must not be null nor empty, must not start with the prefix
     *            "classpath:" but may start with the prefix
     *            "file:" and contain at least one character despite the prefix. On all other cases
     *            a {@link IllegalArgumentException} will be
     *            thrown.
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
                newPathName =
                    new java.io.File(".").getCanonicalPath() + FileTypePrefix.EXTERNAL.removePrefix(pathName);
                LOG.debug("Loading config file from external path: {}", newPathName);
            } catch (final IOException e) {
                LOG.error("Retrieving the current dir failed: ", e);
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
            throw new IllegalStateException(e);
        }
    }

    /**
     * Truncate and overwrite an existing file, or create the file if it doesn't initially exist.
     */
    @Override
    public OutputStream outputStream() throws IOException {
        if (!isWritable()) {
            throw new IllegalStateException(normalizedPathName + " is not writable");
        }
        return Files.newOutputStream(getPath());
    }
}
