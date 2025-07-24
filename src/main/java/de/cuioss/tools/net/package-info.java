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
 * Provides utilities for network operations, URL handling, and SSL support.
 *
 * <h2>Overview</h2>
 * <p>
 * This package offers utilities for handling URLs, internet addresses, and SSL
 * connections.
 * It provides type-safe operations with proper security handling.
 * </p>
 *
 * <h2>Key Components</h2>
 * <ul>
 *   <li><b>URL Handling</b>
 *     <ul>
 *       <li>{@link de.cuioss.tools.net.UrlHelper} - URL manipulation utilities</li>
 *       <li>{@link de.cuioss.tools.net.UrlParameter} - URL parameter handling</li>
 *       <li>{@link de.cuioss.tools.net.ParameterFilter} - Parameter filtering</li>
 *     </ul>
 *   </li>
 *   <li><b>Internet Addresses</b>
 *     <ul>
 *       <li>{@link de.cuioss.tools.net.IDNInternetAddress} - IDN support</li>
 *       <li>Internationalized domain handling</li>
 *     </ul>
 *   </li>
 *   <li><b>SSL Support</b>
 *     <ul>
 *       <li>{@link de.cuioss.tools.net.ssl.KeyStoreProvider} - KeyStore management</li>
 *       <li>{@link de.cuioss.tools.net.ssl.KeyMaterialHolder} - Key material handling</li>
 *       <li>{@link de.cuioss.tools.net.ssl.KeyAlgorithm} - Supported algorithms</li>
 *       <li>{@link de.cuioss.tools.net.ssl.KeyStoreType} - KeyStore types</li>
 *     </ul>
 *   </li>
 *   <li><b>HTTP Utilities</b>
 *     <ul>
 *       <li>{@link de.cuioss.tools.net.http.HttpHandler} - HTTP request/response handling</li>
 *       <li>{@link de.cuioss.tools.net.http.HttpStatusFamily} - HTTP status family detection</li>
 *       <li>{@link de.cuioss.tools.net.http.SecureSSLContextProvider} - Secure SSL context for HTTP</li>
 *     </ul>
 *   </li>
 * </ul>
 *
 * @author Oliver Wolff
 * @see de.cuioss.tools.net.UrlHelper
 * @see de.cuioss.tools.net.UrlParameter
 * @see de.cuioss.tools.net.IDNInternetAddress
 * @see de.cuioss.tools.net.ssl.KeyStoreProvider
 * @see de.cuioss.tools.net.http.HttpHandler
 * @see de.cuioss.tools.net.http.HttpStatusFamily
 * @see de.cuioss.tools.net.http.SecureSSLContextProvider
 */
package de.cuioss.tools.net;
