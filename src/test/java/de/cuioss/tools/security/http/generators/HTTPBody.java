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
package de.cuioss.tools.security.http.generators;

/**
 * Record representing an HTTP request body for testing purposes.
 * This is a temporary implementation for Phase 1 testing that will be 
 * replaced with the actual HTTPBody record from Phase 2/3.
 * 
 * @param content the body content
 * @param contentType the Content-Type header value
 * @param encoding the content encoding (e.g., "gzip", "deflate")
 */
public record HTTPBody(String content, String contentType, String encoding) {
}