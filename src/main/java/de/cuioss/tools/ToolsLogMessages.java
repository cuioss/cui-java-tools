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
package de.cuioss.tools;

import de.cuioss.tools.logging.LogRecord;
import de.cuioss.tools.logging.LogRecordModel;
import lombok.experimental.UtilityClass;

/**
 * Centralized log messages for the cui-java-tools module.
 * Follows the DSL-Style Constants Pattern for organizing log messages by severity level.
 *
 * <h2>Message Identifier Ranges</h2>
 * <ul>
 *   <li>001-099: INFO level</li>
 *   <li>100-199: WARN level</li>
 *   <li>200-299: ERROR level</li>
 *   <li>300-399: FATAL level</li>
 * </ul>
 *
 * <h2>Usage Examples</h2>
 * <pre>
 * import static de.cuioss.tools.ToolsLogMessages.INFO;
 * import static de.cuioss.tools.ToolsLogMessages.WARN;
 * import static de.cuioss.tools.ToolsLogMessages.ERROR;
 *
 * // INFO level
 * LOGGER.info(INFO.CLASSPATH_RESOLUTION_FAILED, path);
 *
 * // WARN level with exception
 * LOGGER.warn(e, WARN.REAL_PATH_RESOLUTION_FAILED, path, e.getMessage());
 *
 * // ERROR level
 * LOGGER.error(e, ERROR.PATH_COMPARISON_FAILED, path1, path2);
 * </pre>
 *
 * @author Oliver Wolff
 * @see de.cuioss.tools.logging.LogRecord
 * @see de.cuioss.tools.logging.LogRecordModel
 */
@UtilityClass
public final class ToolsLogMessages {

    /** Module prefix for all log messages */
    public static final String PREFIX = "CUI_TOOLS";

    /**
     * INFO level log messages (001-099).
     * Used for informational messages that highlight the progress of the application.
     */
    @UtilityClass
    public static final class INFO {

        /**
         * Logged when a resource cannot be resolved from the classpath.
         * Parameters: path
         */
        public static final LogRecord CLASSPATH_RESOLUTION_FAILED = LogRecordModel.builder()
                .template("Unable to resolve '%s' from classpath")
                .prefix(PREFIX)
                .identifier(1)
                .build();
    }

    /**
     * WARN level log messages (100-199).
     * Used for potentially harmful situations that warrant attention.
     */
    @UtilityClass
    public static final class WARN {

        /**
         * Logged when real path resolution fails and falls back to absolute path.
         * Parameters: path, error message
         */
        public static final LogRecord REAL_PATH_RESOLUTION_FAILED = LogRecordModel.builder()
                .template("Unable to resolve real path for '%s', due to '%s'. Returning absolutePath.")
                .prefix(PREFIX)
                .identifier(100)
                .build();

        /**
         * Logged when a file or directory is not accessible.
         * Parameters: path, reason
         */
        public static final LogRecord PATH_NOT_ACCESSIBLE = LogRecordModel.builder()
                .template("File or Directory %s is not accessible, reason: %s")
                .prefix(PREFIX)
                .identifier(101)
                .build();

        /**
         * Logged when field reading via reflection fails.
         * Parameters: field, accessible flag, source object
         */
        public static final LogRecord FIELD_READ_FAILED = LogRecordModel.builder()
                .template("Reading from field '%s' with accessible='%s' and parameter='%s' could not complete")
                .prefix(PREFIX)
                .identifier(102)
                .build();

        /**
         * Logged when wrapper type determination fails.
         * Parameters: type name
         */
        public static final LogRecord WRAPPER_TYPE_DETERMINATION_FAILED = LogRecordModel.builder()
                .template("Unable to determine wrapper type for '%s'")
                .prefix(PREFIX)
                .identifier(103)
                .build();

        /**
         * Logged when generic type extraction fails.
         * Parameters: type
         */
        public static final LogRecord GENERIC_TYPE_DETERMINATION_FAILED = LogRecordModel.builder()
                .template("Unable to determine generic-type for '%s'")
                .prefix(PREFIX)
                .identifier(104)
                .build();
    }

    /**
     * ERROR level log messages (200-299).
     * Used for error events that might still allow the application to continue running.
     */
    @UtilityClass
    public static final class ERROR {

        /**
         * Logged when path comparison fails.
         * Parameters: path1, path2
         */
        public static final LogRecord PATH_COMPARISON_FAILED = LogRecordModel.builder()
                .template("Unable to compare path_a='%s' and path_b='%s'")
                .prefix(PREFIX)
                .identifier(200)
                .build();

        /**
         * Logged when retrieving the current directory fails.
         * Parameters: none
         */
        public static final LogRecord CURRENT_DIR_RETRIEVAL_FAILED = LogRecordModel.builder()
                .template("Retrieving the current dir failed")
                .prefix(PREFIX)
                .identifier(201)
                .build();

        /**
         * Logged when property reading fails.
         * Parameters: property name, bean type
         */
        public static final LogRecord PROPERTY_READ_FAILED = LogRecordModel.builder()
                .template("Failed to read property '%s' from bean of type '%s'")
                .prefix(PREFIX)
                .identifier(202)
                .build();

        /**
         * Logged when property writing fails.
         * Parameters: property name, bean type
         */
        public static final LogRecord PROPERTY_WRITE_FAILED = LogRecordModel.builder()
                .template("Failed to write property '%s' to bean of type '%s'")
                .prefix(PREFIX)
                .identifier(203)
                .build();
    }
}
