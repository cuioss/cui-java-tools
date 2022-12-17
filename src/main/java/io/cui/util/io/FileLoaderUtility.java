package io.cui.util.io;

import static io.cui.util.base.Preconditions.checkArgument;
import static io.cui.util.string.MoreStrings.isEmpty;
import static java.util.Objects.requireNonNull;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

/**
 * Utility class for dealing with generic / classpath related file access.
 *
 * @author Oliver Wolff
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class FileLoaderUtility {

    /**
     * Returns an implementation of {@link FileLoader} matching to the given path.
     *
     * @param pathName must not be null or empty.
     * @return a configured implementation of {@link FileLoader}. In case the pathName is prefixed
     *         with {@link FileTypePrefix#CLASSPATH} it returns a {@link ClassPathLoader}. If prefixed with
     *         {@link FileTypePrefix#URL} it returns a {@link UrlLoader}. Otherwise it returns a
     *         {@link FileSystemLoader}.
     */
    public static FileLoader getLoaderForPath(final String pathName) {
        if (isEmpty(pathName)) {
            throw new IllegalArgumentException("pathName must not be null nor empty");
        }
        if (pathName.startsWith(FileTypePrefix.CLASSPATH.getPrefix())) {
            return new ClassPathLoader(pathName);
        }
        if (pathName.startsWith(FileTypePrefix.URL.getPrefix())) {
            return new UrlLoader(pathName);
        }
        return new FileSystemLoader(pathName);
    }

    /**
     * Helper class that copies the content of a {@link FileLoader} to the temp-folder and
     * references it
     *
     * @param source must not be null and represent an an accessible file, saying
     *            {@link FileLoader#isReadable()}
     * @param markDeleteOnExit if <code>true</code> the file will be marked to delete on Exit.
     * @return a reference on a file copied in the temp folder
     * @throws IOException
     */
    public static Path copyFileToTemp(final FileLoader source, final boolean markDeleteOnExit)
        throws IOException {
        checkArgument(null != source, "Attribute with name source must not be null");
        checkArgument(source.isReadable(), "Source must be readable");

        final Path target = Files.createTempFile(source.getFileName().getNamePart(),
                source.getFileName().getSuffix());

        try (final InputStream inputStream = source.inputStream()) {
            Files.copy(new BufferedInputStream(inputStream), target,
                    StandardCopyOption.REPLACE_EXISTING);
        }
        if (markDeleteOnExit) {
            target.toFile().deleteOnExit();
        }
        return target;
    }

    /**
     * Convenience method for reading the content from a given {@link FileLoader} into a String
     *
     * @param fileLoader must not be null
     * @param charset must not be null
     * @return The String content of the File represented by the given {@link FileLoader}
     * @throws IOException
     */
    public static String toString(final FileLoader fileLoader, final Charset charset) throws IOException {
        requireNonNull(fileLoader);
        final StringWriter writer = new StringWriter();
        try (final InputStream inputStream = fileLoader.inputStream()) {
            IOStreams.copy(inputStream, writer, charset);
        }
        return writer.toString();
    }

    /**
     * Convenience method for reading the content from a given {@link FileLoader} into a String read
     * as UTF-8 String
     *
     * @param fileLoader must not be null
     * @return The String content of the File represented by the given {@link FileLoader}
     * @throws IOException
     */
    public static String toString(final FileLoader fileLoader) throws IOException {
        return toString(fileLoader, StandardCharsets.UTF_8);
    }

    /**
     * Convenience method for reading the content from a given {@link FileLoader} into a String read
     * as UTF-8 String
     *
     * @param fileLoader must not be null
     * @return The String content of the File represented by the given {@link FileLoader}
     * @throws IllegalArgumentException masking the actual {@link IOException}
     * @throws NullPointerException if <code>fileLoader</code> is null
     */
    public static String toStringUnchecked(final FileLoader fileLoader) {
        requireNonNull(fileLoader);
        try {
            return toString(fileLoader);
        } catch (final IOException | IllegalStateException e) {
            throw new IllegalArgumentException("Unable to read from Path " + fileLoader.getFileName(), e);
        }
    }
}
