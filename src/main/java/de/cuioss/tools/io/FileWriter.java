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
     * @return an {@link OutputStream} on the corresponding file. It implicitly
     *         checks {@link #isWritable()} before accessing the file and will throw
     *         an {@link IllegalStateException} in case it is not readable.
     * @throws IOException
     */
    OutputStream outputStream() throws IOException;
}
