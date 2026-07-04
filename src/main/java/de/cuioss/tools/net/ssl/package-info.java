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
/**
 * Provides utilities for SSL/TLS key material and keystore handling.
 *
 * <h2>Overview</h2>
 * <p>
 * This package offers type-safe abstractions for configuring keystores and
 * truststores, either from the file system or from in-memory key material.
 * </p>
 *
 * <h2>Key Components</h2>
 * <ul>
 *   <li>{@link de.cuioss.tools.net.ssl.KeyStoreProvider} - Creates
 *       {@link java.security.KeyStore} instances from a file location or from
 *       provided key material</li>
 *   <li>{@link de.cuioss.tools.net.ssl.KeyMaterialHolder} - Container for
 *       in-memory key material and its metadata</li>
 *   <li>{@link de.cuioss.tools.net.ssl.KeyStoreType} - Distinguishes keystore
 *       and truststore usage</li>
 *   <li>{@link de.cuioss.tools.net.ssl.KeyHolderType} - Describes the kind of
 *       key material (single key vs. serialized keystore)</li>
 *   <li>{@link de.cuioss.tools.net.ssl.KeyAlgorithm} - Supported key
 *       algorithms</li>
 * </ul>
 *
 * @author Oliver Wolff
 */
package de.cuioss.tools.net.ssl;
