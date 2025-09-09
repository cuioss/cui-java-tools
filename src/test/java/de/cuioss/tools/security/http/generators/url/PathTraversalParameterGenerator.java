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
package de.cuioss.tools.security.http.generators.url;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.TypedGenerator;

/**
 * Generator for URL parameter values containing path traversal attacks.
 * Provides parameter VALUES (not full "name=value" strings) with various path traversal patterns.
 * These values are designed to be detected by URLParameterValidationPipeline.
 */
public class PathTraversalParameterGenerator implements TypedGenerator<String> {

    private final TypedGenerator<String> pathTraversalParameters = Generators.fixedValues(
            "..%2F..%2Fetc%2Fpasswd",            // Encoded path traversal
            "%2E%2E%2F%2E%2E%2Fconfig",          // Double encoded traversal
            "%2e%2e%5c%2e%2e%5cwindows",         // Mixed encoding
            "..%5c..%5c..%5croot",               // Windows style traversal
            "..%2F..%2Fshadow",                  // Simple traversal
            "%2e%2e%2f%2e%2e%2fetc%2fhosts",     // Mixed case encoding
            "..%5c..%5csystem32%5cdrivers%5cetc%5chosts", // Windows paths
            "%2e%2e%2f%2e%2e%2f%2e%2e%2froot%2f.ssh%2fid_rsa", // Deep traversal
            "..%2f..%2fvar%2flog%2fauth.log",    // Log files
            "%2e%2e%5c%2e%2e%5cwindows%5csystem32%5cconfig%5csam", // Registry
            "....%2f....%2f....%2fetc%2fpasswd", // Quad-dot bypass
            "%252e%252e%252f%252e%252e%252fboot.ini", // Double encoded
            "..%c0%af..%c0%afetc%c0%afpasswd",   // UTF-8 overlong
            "%c0%ae%c0%ae%c0%afetc%c0%afhosts"   // UTF-8 overlong alt
    );

    @Override
    public String next() {
        return pathTraversalParameters.next();
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}