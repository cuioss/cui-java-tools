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
 * Generates double and multiple encoding attack patterns.
 * Focuses specifically on double encoding bypass techniques for security testing.
 * 
 * Implements: Task G5 from HTTP verification specification
 */
public class DoubleEncodingAttackGenerator implements TypedGenerator<String> {

    private final TypedGenerator<String> doubleEncodingPatterns = Generators.fixedValues(
            // Classic double encoding patterns
            "%252e%252e%252f../../../etc/passwd",
            "%252e%252e%252f%252e%252e%252f%252e%252e%252f",

            // CVE-2021-42013: Apache double encoding bypass
            "%%32%65",                                              // %2e double encoded
            "%%32%66",                                              // %2f double encoded
            "/icons%%32%65%%32%65/etc/passwd",
            "/cgi-bin/.%%32%65/%%32%65%%32%65/etc/passwd",

            // Mixed single/double encoding
            "%2e%252e%2f../etc/passwd",
            "%252e%2e%252f%2e%2e/etc/shadow",

            // Triple encoding
            "%25252e%25252e%25252f",
            "%252525%252e%252525%2e%252525%2f",

            // Case variations in double encoding
            "%252E%252E%252F",
            "%252e%252E%252f%252F",

            // Windows path separators
            "%255c%252e%252e%255c",
            "%252e%252e%255c%252e%252e%255c",

            // Combined with legitimate paths
            "/api/v1%252e%252e%252f%252e%252e%252fadmin",
            "/files%252f%252e%252e%252f%252e%252e%252fconfig",

            // Deep double encoding
            "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f",

            // Windows specific double encoding
            "/scripts%%35%63%%32%65%%32%65/cmd.exe",
            "/inetpub%%35%63%%32%65%%32%65/wwwroot",

            // Additional path traversal double encoding
            "/api%%32%65%%32%65%%32%66%%32%65%%32%65/config",
            "/upload%%32%66%%32%65%%32%65%%32%66%%32%65%%32%65/admin",

            // Mixed with normal paths
            "/admin%252e%252e%252f%252e%252e%252fconfig",
            "/backup%252f%252e%252e%252fadmin%252fpasswords"
    );

    @Override
    public String next() {
        return doubleEncodingPatterns.next();
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}