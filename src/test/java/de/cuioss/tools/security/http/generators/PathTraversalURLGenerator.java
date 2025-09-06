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

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.TypedGenerator;

/**
 * Generator for URL paths containing path traversal attacks.
 * Provides various encoded path traversal patterns in URL context.
 */
public class PathTraversalURLGenerator implements TypedGenerator<String> {

    private final TypedGenerator<String> pathTraversalURLs = Generators.fixedValues(
            "/api/%2E%2E/admin",              // Encoded ..
            "/api/users/%2E%2E/%2E%2E/%2E%2E/etc/passwd", // Multiple encoded traversal
            "/api/users/%2E/%2E%2E/admin",    // Encoded ./../
            "/api/users/%2E%2E%5Cadmin",      // Windows style encoded
            "/api/users/%2e%2e/admin",        // Lowercase encoded traversal
            "/api/%2e%2e%2f%2e%2e%2froot",    // Double encoded traversal
            "/api/files/%2E%2E%2F%2E%2E%2Fconfig", // Config file access
            "/api/docs/%2e%2e%5c%2e%2e%5cwindows", // Windows traversal
            "/api/admin/%2E%2E/../../etc/shadow", // Mixed traversal
            "/api/download/%2e%2e%2fetc%2fhosts", // Hosts file access
            "/api/backup/%2E%2E%2F%2E%2E%2Fvar%2Flog", // Log directory access
            "/api/upload/%2e%2e%5c%2e%2e%5csystem32", // System32 access
            "/api/files/..%2f..%2fetc%2fpasswd", // Mixed encoding
            "/api/data/%252e%252e%252f%252e%252e%252f", // Double URL encoded
            "/api/content/%2E%2E%2F%2E%2E%2F%2E%2E%2Froot%2F.ssh" // SSH keys access
    );

    @Override
    public String next() {
        return pathTraversalURLs.next();
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}