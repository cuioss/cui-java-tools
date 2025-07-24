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
     * This method should be within a {@code try-with-resources} statement as it is
     * not closed by the implementation.
     *
     * @return an {@link InputStream} on the corresponding file. It implicitly
     *         checks {@link #isReadable()} before accessing the file and will throw
     *         an {@link IllegalStateException} in case it is not readable.
     * @throws IOException
     */
    InputStream inputStream() throws IOException;

    /**
     * @return an {@link URL} on the corresponding file.
     */
    URL getURL();

    /**
     * @return boolean indicating that the loader loads from the file-system and not
     *         from the classpath
     */
    boolean isFilesystemLoader();
}
