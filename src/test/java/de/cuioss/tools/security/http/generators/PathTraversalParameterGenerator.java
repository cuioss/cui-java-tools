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
 * Generator for URL parameters containing path traversal attacks.
 * Provides parameter strings with various path traversal patterns.
 */
public class PathTraversalParameterGenerator implements TypedGenerator<String> {

    private final TypedGenerator<String> pathTraversalParameters = Generators.fixedValues(
            "param=..%2F..%2Fetc%2Fpasswd",      // Encoded path traversal
            "file=%2E%2E%2F%2E%2E%2Fconfig",     // Double encoded traversal
            "path=%2e%2e%5c%2e%2e%5cwindows",    // Mixed encoding
            "param=..%5c..%5c..%5croot",         // Windows style traversal
            "file=..%2F..%2Fshadow",
            "config=%2e%2e%2f%2e%2e%2fetc%2fhosts",
            "document=..%5c..%5csystem32%5cdrivers%5cetc%5chosts",
            "path=%2e%2e%2f%2e%2e%2f%2e%2e%2froot%2f.ssh%2fid_rsa",
            "backup=..%2f..%2fvar%2flog%2fauth.log",
            "log=%2e%2e%5c%2e%2e%5cwindows%5csystem32%5cconfig%5csam",
            "data=....%2f....%2f....%2fetc%2fpasswd",
            "target=%252e%252e%252f%252e%252e%252fboot.ini",
            "source=..%c0%af..%c0%afetc%c0%afpasswd",
            "file=%c0%ae%c0%ae%c0%afetc%c0%afhosts"
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