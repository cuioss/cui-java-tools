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
package de.cuioss.tools.codec;

import java.io.Serial;

/**
 * Thrown when there is a failure condition during the decoding process. This
 * exception is thrown when a Decoder encounters a decoding specific exception
 * such as invalid data, or characters outside the expected range.
 *
 * @see <a href="https://github.com/apache/commons-codec/blob/master/src/main/java/org/apache/commons/codec/DecoderException.java">commons-codec/</a>
 */
public class DecoderException extends Exception {

    /**
     * Declares the Serial Version Uid.
     *
     * @see <a href="http://c2.com/cgi/wiki?AlwaysDeclareSerialVersionUid">Always
     * Declare Serial Version Uid</a>
     */
    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new exception with {@code null} as its detail message. The cause
     * is not initialized, and may subsequently be initialized by a call to
     * {@link #initCause}.
     */
    public DecoderException() {
    }

    /**
     * Constructs a new exception with the specified detail message. The cause is
     * not initialized, and may subsequently be initialized by a call to
     * {@link #initCause}.
     *
     * @param message The detail message which is saved for later retrieval by the
     *                {@link #getMessage()} method.
     */
    public DecoderException(final String message) {
        super(message);
    }

    /**
     * Constructs a new exception with the specified detail message and cause.
     * <p>
     * Note that the detail message associated with {@code cause} is not
     * automatically incorporated into this exception's detail message.
     *
     * @param message The detail message which is saved for later retrieval by the
     *                {@link #getMessage()} method.
     * @param cause   The cause which is saved for later retrieval by the
     *                {@link #getCause()} method. A {@code null} value is permitted,
     *                and indicates that the cause is nonexistent or unknown.
     */
    public DecoderException(final String message, final Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs a new exception with the specified cause and a detail message of
     * <code>(cause==null ?
     * null : cause.toString())</code> (which typically contains the class and
     * detail message of {@code cause}). This constructor is useful for exceptions
     * that are little more than wrappers for other throwables.
     *
     * @param cause The cause which is saved for later retrieval by the
     *              {@link #getCause()} method. A {@code null} value is permitted,
     *              and indicates that the cause is nonexistent or unknown.
     */
    public DecoderException(final Throwable cause) {
        super(cause);
    }
}
