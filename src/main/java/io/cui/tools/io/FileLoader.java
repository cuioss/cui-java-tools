package io.cui.tools.io;

import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.net.URL;

/**
 * Wraps different ways file loading: FileSystem (absolute), Classpath,..
 * <p>
 * The implementations must be reentrant regarding {@link #inputStream()}
 * </p>
 *
 * @author Oliver Wolff
 */
public interface FileLoader extends Serializable {

    /**
     * @return boolean indicating whether the concrete file exists and is accessible
     */
    boolean isReadable();

    /**
     * @return the filename in an appropriate presentation.
     */
    StructuredFilename getFileName();

    /**
     * This method should be within a {@code try-with-resources} statement as it is not closed by
     * the implementation.
     *
     * @return an {@link InputStream} on the corresponding file. It implicitly checks
     *         {@link #isReadable()} before accessing the file and will throw an
     *         {@link IllegalStateException} in case it is not readable.
     * @throws IOException
     */
    InputStream inputStream() throws IOException;

    /**
     * @return an {@link URL} on the corresponding file.
     */
    URL getURL();

    /**
     * @return boolean indicating that the loader loads from the file-system and not from the
     *         classpath
     */
    boolean isFilesystemLoader();
}
