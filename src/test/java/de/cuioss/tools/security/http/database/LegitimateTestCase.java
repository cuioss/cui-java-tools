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
package de.cuioss.tools.security.http.database;

/**
 * Test case record for legitimate URL patterns that should pass validation without triggering
 * false positives. This is the counterpart to {@link AttackTestCase} for valid inputs.
 * 
 * <p><strong>FALSE POSITIVE PREVENTION:</strong> This record represents legitimate URL patterns
 * that must be accepted by the security validation system. These patterns help ensure the
 * validation logic doesn't incorrectly reject valid business use cases.</p>
 * 
 * <h3>Design Principles</h3>
 * <ul>
 *   <li><strong>Valid Patterns</strong> - All patterns represent legitimate, safe URLs</li>
 *   <li><strong>Business Use Cases</strong> - Covers real-world URL patterns from applications</li>
 *   <li><strong>Edge Cases</strong> - Includes unusual but valid URL constructs</li>
 *   <li><strong>Documentation</strong> - Clear rationale for why each pattern is legitimate</li>
 * </ul>
 * 
 * @param legitimatePattern The legitimate URL pattern that should pass validation
 * @param description Description of the legitimate use case this pattern represents
 * @param acceptanceRationale Explanation of why this pattern must be accepted
 * 
 * @since 2.5
 */
public record LegitimateTestCase(
        String legitimatePattern,
        String description,
        String acceptanceRationale) {

    /**
     * Creates a compact summary suitable for test failure messages.
     * 
     * @return A brief summary containing the pattern and first 50 characters of description
     */
    public String getCompactSummary() {
        String truncatedDescription = description.length() > 50 
                ? description.substring(0, 47) + "..." 
                : description;
        return String.format("Pattern: %s | %s", legitimatePattern, truncatedDescription);
    }

    @Override
    public String toString() {
        return String.format("LegitimateTestCase[pattern='%s', description='%s']", 
                legitimatePattern, 
                description.length() > 30 ? description.substring(0, 27) + "..." : description);
    }
}