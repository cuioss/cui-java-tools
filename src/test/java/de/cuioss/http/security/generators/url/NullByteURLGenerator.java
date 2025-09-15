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
package de.cuioss.http.security.generators.url;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.TypedGenerator;

/**
 * Generator for URL paths containing null byte injection attacks.
 *
 * <p><strong>CRITICAL NULL BYTE SECURITY DATABASE:</strong> This generator contains precise
 * null byte injection attack patterns that exploit URL parsing vulnerabilities where null bytes
 * (\u0000 and %00 encoded) can bypass security filters or cause path truncation in various
 * web servers and application frameworks.</p>
 *
 * <p><strong>QI-6 CONVERSION STATUS:</strong> NOT SUITABLE for dynamic conversion.
 * Null byte attacks require exact character sequences and encoding combinations where
 * the position and encoding of the null byte is critical for attack effectiveness
 * (e.g., file.jpg\u0000.php vs file.jpg%00.php). These precise patterns
 * cannot be algorithmically generated without losing attack effectiveness.</p>
 *
 * <h3>Null Byte Attack Database</h3>
 * <ul>
 *   <li><strong>Path truncation:</strong> {@code /api/users\0admin} - Null byte truncates path processing</li>
 *   <li><strong>URL encoded bypass:</strong> {@code /api/users%00admin} - Encoded null byte bypasses filters</li>
 *   <li><strong>File extension bypass:</strong> {@code /api/files\0.php} - Null byte truncates extension check</li>
 *   <li><strong>Directory traversal combination:</strong> {@code /api/download\0../../../etc/passwd} - Mixed attack vectors</li>
 *   <li><strong>MIME type confusion:</strong> {@code /api/upload/file.jpg\0.php} - Bypasses MIME validation</li>
 * </ul>
 *
 * <h3>Null Byte Attack Mechanics</h3>
 * <ul>
 *   <li><strong>String termination:</strong> C-style string processing terminates at null byte</li>
 *   <li><strong>Filter bypass:</strong> Security filters may not process beyond null byte</li>
 *   <li><strong>Path truncation:</strong> File system operations may truncate at null byte</li>
 *   <li><strong>Extension spoofing:</strong> File extension checks bypassed by null byte insertion</li>
 *   <li><strong>Encoding variations:</strong> Different null byte encodings bypass different filters</li>
 * </ul>
 *
 * <p><strong>PRESERVATION RATIONALE:</strong> Null byte attacks depend on exact character
 * positioning and encoding combinations. Each pattern represents a specific vulnerability
 * in URL processing that must be preserved exactly. Algorithmic generation cannot reproduce
 * the precise character sequences and encoding variations required for effective
 * null byte injection testing.</p>
 *
 * Provides various null byte patterns in URL context for security testing.
 */
public class NullByteURLGenerator implements TypedGenerator<String> {

    private final TypedGenerator<String> nullByteURLs = Generators.fixedValues(
            "/api/users\0admin",
            "/api/users%00admin",
            "/api\0/users",
            "/api/users/123\0",
            "/api/files\0.php",
            "/api/download\0../../../etc/passwd",
            "/api/config%00.txt",
            "/api/upload/file.jpg\0.php",
            "/api/docs/readme\0.html",
            "/api/admin\0/secret",
            "/api/data%00/config",
            "/api/backup\0.tar.gz",
            "/api/logs/error.log\0",
            "/api/scripts%00.sh",
            "/api/images/photo.png\0.php"
    );

    @Override
    public String next() {
        return nullByteURLs.next();
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}