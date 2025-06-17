/**
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
/**
 * Provides comprehensive I/O utilities for file and resource handling.
 *
 * <h2>Overview</h2>
 * <p>
 * This package offers utilities for file operations, resource loading, and stream
 * handling.
 * It provides type-safe operations with proper resource management.
 * </p>
 *
 * <h2>Key Components</h2>
 * <ul>
 *   <li><b>Resource Loading</b>
 *     <ul>
 *       <li>{@link de.cuioss.tools.io.ClassPathLoader} - Classpath resource loading</li>
 *       <li>{@link de.cuioss.tools.io.FileSystemLoader} - File system access</li>
 *       <li>{@link de.cuioss.tools.io.UrlLoader} - URL-based resource loading</li>
 *     </ul>
 *   </li>
 *   <li><b>File Operations</b>
 *     <ul>
 *       <li>{@link de.cuioss.tools.io.FileLoaderUtility} - File loading utilities</li>
 *       <li>{@link de.cuioss.tools.io.FileLoader} - File loading interface</li>
 *       <li>{@link de.cuioss.tools.io.FilenameUtils} - Filename operations</li>
 *       <li>{@link de.cuioss.tools.io.MorePaths} - Enhanced path handling</li>
 *     </ul>
 *   </li>
 *   <li><b>Stream Handling</b>
 *     <ul>
 *       <li>{@link de.cuioss.tools.io.IOStreams} - Stream utilities</li>
 *       <li>{@link de.cuioss.tools.io.IOCase} - Case sensitivity handling</li>
 *       <li>Stream copying and conversion</li>
 *     </ul>
 *   </li>
 * </ul>
 *
 * <h2>Usage Examples</h2>
 * <pre>
 * // Loading classpath resources
 * try {
 *     String content = ClassPathLoader.readFromClasspath("config/app.properties");
 *     LOGGER.info("Loaded content: %s", content);
 * } catch (IOException e) {
 *     LOGGER.error(e, "Failed to load resource");
 * }
 *
 * // File operations
 * Path file = Paths.get("data.txt");
 * if (MorePaths.checkReadableFile(file)) {
 *     String content = FileLoaderUtility.loadFileFromPath(file);
 *     LOGGER.info("Loaded file content: %s", content);
 * }
 *
 * // Stream handling
 * try (InputStream input = new FileInputStream("input.txt");
 *      OutputStream output = new FileOutputStream("output.txt")) {
 *     IOStreams.copy(input, output);
 * } catch (IOException e) {
 *     LOGGER.error(e, "Failed to copy file");
 * }
 *
 * // Filename handling
 * String filename = "document.txt";
 * String extension = FilenameUtils.getExtension(filename);
 * String baseName = FilenameUtils.getBaseName(filename);
 * </pre>
 *
 * <h2>Best Practices</h2>
 * <ul>
 *   <li>Always use try-with-resources for streams</li>
 *   <li>Handle IOExceptions properly</li>
 *   <li>Validate paths before operations</li>
 * </ul>
 *
 * @author Oliver Wolff
 * @see de.cuioss.tools.io.IOStreams
 * @see de.cuioss.tools.io.FilenameUtils
 * @see de.cuioss.tools.io.MorePaths
 * @see de.cuioss.tools.io.ClassPathLoader
 */
package de.cuioss.tools.io;
