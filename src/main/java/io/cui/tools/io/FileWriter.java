package io.cui.tools.io;

import java.io.IOException;
import java.io.OutputStream;
import java.io.Serializable;

/**
 * Interface for file writer operations.
 *
 * @author Sven Haag
 */
public interface FileWriter extends Serializable {

    /**
     *
     * @return true if an actual file is writable.
     */
    boolean isWritable();

    /**
     * @return the filename in an appropriate presentation.
     */
    StructuredFilename getFileName();

    /**
     * @return an {@link OutputStream} on the corresponding file. It implicitly checks
     *         {@link #isWritable()} before accessing the file and will throw an
     *         {@link IllegalStateException} in case it is not readable.
     * @throws IOException
     */
    OutputStream outputStream() throws IOException;
}
