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

import de.cuioss.test.generator.TypedGenerator;

/**
 * Generator for algorithmic complexity attack patterns that test DoS vulnerabilities
 * through computationally expensive operations that can exhaust CPU, memory, or processing time.
 *
 * <p>Generates 15 different types of algorithmic complexity attacks:
 * <ul>
 *   <li>Regex ReDoS (Regular Expression Denial of Service)</li>
 *   <li>Exponential backtracking patterns</li>
 *   <li>Hash collision attacks (algorithmic complexity)</li>
 *   <li>Deep recursion patterns</li>
 *   <li>Nested loop complexity attacks</li>
 *   <li>Polynomial time complexity exploits</li>
 *   <li>Exponential time complexity exploits</li>
 *   <li>Memory allocation complexity attacks</li>
 *   <li>String comparison timing attacks</li>
 *   <li>Sorting algorithm complexity exploits</li>
 *   <li>Graph traversal complexity attacks</li>
 *   <li>XML parser complexity bombs</li>
 *   <li>JSON parser complexity attacks</li>
 *   <li>URL parsing complexity exploits</li>
 *   <li>Pattern matching complexity attacks</li>
 * </ul>
 *
 * <p>Each attack type includes multiple specific attack patterns designed to trigger
 * worst-case algorithmic behavior in URL processing, parsing, and validation systems.
 *
 * <p>Based on OWASP guidelines for complexity attack prevention and
 * CWE-407: Inefficient Algorithmic Complexity, CWE-1333: Inefficient Regular Expression Complexity.
 *
 * @author Security Test Framework
 * @see <a href="https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS">OWASP ReDoS</a>
 * @see <a href="https://cwe.mitre.org/data/definitions/407.html">CWE-407</a>
 * @see <a href="https://cwe.mitre.org/data/definitions/1333.html">CWE-1333</a>
 */
public class AlgorithmicComplexityAttackGenerator implements TypedGenerator<String> {

    private final AttackTypeSelector attackTypeSelector = new AttackTypeSelector(15);

    @Override
    public String next() {
        // Use base pattern that should normally pass validation
        String basePattern = "https://example.com/api/complexity";

        return switch (attackTypeSelector.nextAttackType()) {
            case 0 -> createRegexRedosAttack(basePattern);
            case 1 -> createExponentialBacktrackingAttack(basePattern);
            case 2 -> createHashCollisionAttack(basePattern);
            case 3 -> createDeepRecursionAttack(basePattern);
            case 4 -> createNestedLoopComplexityAttack(basePattern);
            case 5 -> createPolynomialTimeComplexityAttack(basePattern);
            case 6 -> createExponentialTimeComplexityAttack(basePattern);
            case 7 -> createMemoryAllocationComplexityAttack(basePattern);
            case 8 -> createStringComparisonTimingAttack(basePattern);
            case 9 -> createSortingAlgorithmComplexityAttack(basePattern);
            case 10 -> createGraphTraversalComplexityAttack(basePattern);
            case 11 -> createXmlParserComplexityBomb(basePattern);
            case 12 -> createJsonParserComplexityAttack(basePattern);
            case 13 -> createUrlParsingComplexityAttack(basePattern);
            case 14 -> createPatternMatchingComplexityAttack(basePattern);
            default -> throw new IllegalStateException("Invalid attack type");
        };
    }

    private String createRegexRedosAttack(String pattern) {
        // ReDoS patterns that cause exponential backtracking in regex engines
        String[] redosPatterns = {
                pattern + "?input=" + createCatastrophicBacktrackingPattern("a", "b", 20),
                pattern + "?data=" + createNestedQuantifierPattern("x", "y", 15),
                pattern + "?query=" + createAlternationBacktrackingPattern("test", "data", 25),
                pattern + "?param=" + createGroupedQuantifierPattern("abc", 30),
                pattern + "?value=" + createOverlappingQuantifierPattern("123", "456", 18),
        };
        return redosPatterns[hashBasedSelection(redosPatterns.length)];
    }

    private String createExponentialBacktrackingAttack(String pattern) {
        // Patterns that trigger exponential backtracking behavior
        String[] backtrackingAttacks = {
                pattern + "?bt=" + generateExponentialPattern("(a+)+", "a", 20) + "X",
                pattern + "?exp=" + generateExponentialPattern("(x*)*", "x", 25) + "Y",
                pattern + "?back=" + generateExponentialPattern("(.*)*", ".", 15) + "Z",
                pattern + "?track=" + generateExponentialPattern("(a|a)*", "a", 30) + "B",
                pattern + "?complex=" + generateExponentialPattern("(b+)+", "b", 22) + "C",
        };
        return backtrackingAttacks[hashBasedSelection(backtrackingAttacks.length)];
    }

    private String createHashCollisionAttack(String pattern) {
        // Hash collision attacks targeting algorithmic complexity
        String[] hashCollisionAttacks = {
                pattern + "?hash=" + generateHashCollisionPayload("Aa", "BB", 16),
                pattern + "?collision=" + generateHashCollisionPayload("AaAa", "BBBB", 8),
                pattern + "?bucket=" + generateHashCollisionPayload("Aa", "BB", 20),
                pattern + "?table=" + generateHashCollisionPayload("AaAaAa", "BBBBBB", 6),
                pattern + "?map=" + generateHashCollisionPayload("AaBB", "BaAB", 12),
        };
        return hashCollisionAttacks[hashBasedSelection(hashCollisionAttacks.length)];
    }

    private String createDeepRecursionAttack(String pattern) {
        // Deep recursion patterns that can cause stack overflow
        String[] recursionAttacks = {
                pattern + "?recurse=" + createDeepNestedStructure("(", ")", 1000),
                pattern + "?deep=" + createDeepNestedStructure("[", "]", 500),
                pattern + "?nested=" + createDeepNestedStructure("{", "}", 800),
                pattern + "?stack=" + createDeepNestedStructure("<", ">", 600),
                pattern + "?depth=" + createDeepNestedStructure("((", "))", 400),
        };
        return recursionAttacks[hashBasedSelection(recursionAttacks.length)];
    }

    private String createNestedLoopComplexityAttack(String pattern) {
        // Patterns that trigger nested loop behavior (O(n²) or worse)
        String[] nestedLoopAttacks = {
                pattern + "?nested=" + generateNestedComplexityPattern("ABAB", 50),
                pattern + "?loop=" + generateNestedComplexityPattern("XYZX", 40),
                pattern + "?quadratic=" + generateNestedComplexityPattern("1212", 60),
                pattern + "?cubic=" + generateNestedComplexityPattern("ABCABC", 35),
                pattern + "?polynomial=" + generateNestedComplexityPattern("XYXY", 45),
        };
        return nestedLoopAttacks[hashBasedSelection(nestedLoopAttacks.length)];
    }

    private String createPolynomialTimeComplexityAttack(String pattern) {
        // Polynomial time complexity attacks (O(n²), O(n³), etc.)
        String[] polynomialAttacks = {
                pattern + "?poly=" + generatePolynomialPattern("ABC", 100),
                pattern + "?quadratic=" + generatePolynomialPattern("XYZ", 80),
                pattern + "?cubic=" + generatePolynomialPattern("123", 120),
                pattern + "?quartic=" + generatePolynomialPattern("ABCD", 70),
                pattern + "?complex=" + generatePolynomialPattern("WXYZ", 90),
        };
        return polynomialAttacks[hashBasedSelection(polynomialAttacks.length)];
    }

    private String createExponentialTimeComplexityAttack(String pattern) {
        // Exponential time complexity attacks (O(2^n), O(3^n), etc.)
        String[] exponentialAttacks = {
                pattern + "?exp=" + generateExponentialComplexityPattern("AB", 25),
                pattern + "?double=" + generateExponentialComplexityPattern("XY", 20),
                pattern + "?triple=" + generateExponentialComplexityPattern("ABC", 18),
                pattern + "?factorial=" + generateExponentialComplexityPattern("ABCD", 15),
                pattern + "?exponential=" + generateExponentialComplexityPattern("12", 30),
        };
        return exponentialAttacks[hashBasedSelection(exponentialAttacks.length)];
    }

    private String createMemoryAllocationComplexityAttack(String pattern) {
        // Memory allocation complexity attacks
        String[] memoryAttacks = {
                pattern + "?memory=" + generateMemoryComplexityPattern(10000),
                pattern + "?alloc=" + generateMemoryComplexityPattern(50000),
                pattern + "?heap=" + generateMemoryComplexityPattern(25000),
                pattern + "?buffer=" + generateMemoryComplexityPattern(75000),
                pattern + "?space=" + generateMemoryComplexityPattern(100000),
        };
        return memoryAttacks[hashBasedSelection(memoryAttacks.length)];
    }

    private String createStringComparisonTimingAttack(String pattern) {
        // String comparison timing attacks
        String[] timingAttacks = {
                pattern + "?timing=" + generateTimingAttackPattern("password", 100),
                pattern + "?compare=" + generateTimingAttackPattern("secret", 80),
                pattern + "?time=" + generateTimingAttackPattern("token", 120),
                pattern + "?delay=" + generateTimingAttackPattern("key", 90),
                pattern + "?slow=" + generateTimingAttackPattern("auth", 110),
        };
        return timingAttacks[hashBasedSelection(timingAttacks.length)];
    }

    private String createSortingAlgorithmComplexityAttack(String pattern) {
        // Sorting algorithm worst-case complexity attacks
        String[] sortingAttacks = {
                pattern + "?sort=" + generateWorstCaseSortPattern(1000),
                pattern + "?order=" + generateWorstCaseSortPattern(500),
                pattern + "?arrange=" + generateWorstCaseSortPattern(2000),
                pattern + "?sequence=" + generateWorstCaseSortPattern(800),
                pattern + "?bubble=" + generateWorstCaseSortPattern(1200),
        };
        return sortingAttacks[hashBasedSelection(sortingAttacks.length)];
    }

    private String createGraphTraversalComplexityAttack(String pattern) {
        // Graph traversal complexity attacks
        String[] graphAttacks = {
                pattern + "?graph=" + generateComplexGraphPattern(50, 100),
                pattern + "?traverse=" + generateComplexGraphPattern(30, 200),
                pattern + "?path=" + generateComplexGraphPattern(80, 150),
                pattern + "?cycle=" + generateComplexGraphPattern(40, 300),
                pattern + "?tree=" + generateComplexGraphPattern(60, 250),
        };
        return graphAttacks[hashBasedSelection(graphAttacks.length)];
    }

    private String createXmlParserComplexityBomb(String pattern) {
        // XML parser complexity bombs
        String[] xmlBombs = {
                pattern + "?xml=" + generateXmlComplexityBomb(50),
                pattern + "?xmldoc=" + generateXmlComplexityBomb(30),
                pattern + "?xmldata=" + generateXmlComplexityBomb(80),
                pattern + "?xmlparse=" + generateXmlComplexityBomb(40),
                pattern + "?xmlbomb=" + generateXmlComplexityBomb(60),
        };
        return xmlBombs[hashBasedSelection(xmlBombs.length)];
    }

    private String createJsonParserComplexityAttack(String pattern) {
        // JSON parser complexity attacks
        String[] jsonAttacks = {
                pattern + "?json=" + generateJsonComplexityAttack(100),
                pattern + "?jsondata=" + generateJsonComplexityAttack(50),
                pattern + "?jsonparse=" + generateJsonComplexityAttack(200),
                pattern + "?jsonbomb=" + generateJsonComplexityAttack(80),
                pattern + "?jsondeep=" + generateJsonComplexityAttack(150),
        };
        return jsonAttacks[hashBasedSelection(jsonAttacks.length)];
    }

    private String createUrlParsingComplexityAttack(String pattern) {
        // URL parsing complexity attacks
        String[] urlParsingAttacks = {
                generateComplexUrlPattern(pattern, 500),
                generateComplexUrlPattern(pattern, 300),
                generateComplexUrlPattern(pattern, 800),
                generateComplexUrlPattern(pattern, 400),
                generateComplexUrlPattern(pattern, 600),
        };
        return urlParsingAttacks[hashBasedSelection(urlParsingAttacks.length)];
    }

    private String createPatternMatchingComplexityAttack(String pattern) {
        // Pattern matching complexity attacks
        String[] patternAttacks = {
                pattern + "?pattern=" + generateComplexPatternMatch("AAAAAAAA", "AAAAAAAB", 100),
                pattern + "?match=" + generateComplexPatternMatch("XXXXXXXX", "XXXXXXXY", 80),
                pattern + "?search=" + generateComplexPatternMatch("12121212", "12121213", 120),
                pattern + "?find=" + generateComplexPatternMatch("ABABABAB", "ABABABAC", 90),
                pattern + "?locate=" + generateComplexPatternMatch("XYZXYZXY", "XYZXYZXZ", 110),
        };
        return patternAttacks[hashBasedSelection(patternAttacks.length)];
    }

    // Helper methods for generating various complexity attack patterns

    private String createCatastrophicBacktrackingPattern(String a, String b, int length) {
        // Creates patterns like (a+)+b repeated 'length' times
        return "(" + a.repeat(length) + ")++" + b;
    }

    private String createNestedQuantifierPattern(String base, String suffix, int depth) {
        StringBuilder pattern = new StringBuilder();
        for (int i = 0; i < depth; i++) {
            pattern.append("(").append(base).append("*)*");
        }
        pattern.append(suffix);
        return pattern.toString();
    }

    private String createAlternationBacktrackingPattern(String alt1, String alt2, int repetitions) {
        String basePattern = "(" + alt1 + "|" + alt1 + ")*";
        return basePattern + alt2.repeat(repetitions);
    }

    private String createGroupedQuantifierPattern(String base, int groups) {
        StringBuilder pattern = new StringBuilder();
        for (int i = 0; i < groups; i++) {
            pattern.append("(").append(base).append("*)*");
        }
        return pattern.toString();
    }

    private String createOverlappingQuantifierPattern(String pattern1, String pattern2, int overlap) {
        return "(" + pattern1.repeat(overlap) + "|" + pattern1.repeat(overlap) + ")*" + pattern2;
    }

    private String generateExponentialPattern(String basePattern, String character, int repetitions) {
        return basePattern + character.repeat(repetitions);
    }

    private String generateHashCollisionPayload(String collision1, String collision2, int pairs) {
        StringBuilder payload = new StringBuilder();
        for (int i = 0; i < pairs; i++) {
            payload.append(collision1).append(collision2);
        }
        return payload.toString();
    }

    private String createDeepNestedStructure(String open, String close, int depth) {
        StringBuilder structure = new StringBuilder();
        // Build opening brackets
        for (int i = 0; i < depth; i++) {
            structure.append(open);
        }
        structure.append("DEEP");
        // Build closing brackets
        for (int i = 0; i < depth; i++) {
            structure.append(close);
        }
        return structure.toString();
    }

    private String generateNestedComplexityPattern(String base, int repetitions) {
        // Generate pattern that causes nested loop behavior
        StringBuilder pattern = new StringBuilder();
        for (int i = 0; i < repetitions; i++) {
            pattern.append(base).append(i % 10);
        }
        return pattern.toString();
    }

    private String generatePolynomialPattern(String base, int size) {
        // Generate pattern that causes polynomial time complexity
        StringBuilder pattern = new StringBuilder("POLY:");
        for (int i = 0; i < size; i++) {
            for (int j = 0; j <= i; j++) {
                pattern.append(base).append(j);
            }
        }
        return pattern.toString();
    }

    private String generateExponentialComplexityPattern(String base, int depth) {
        // Generate pattern that causes exponential time complexity
        if (depth <= 0) return base;
        String subPattern = generateExponentialComplexityPattern(base, depth - 1);
        return subPattern + subPattern;
    }

    private String generateMemoryComplexityPattern(int size) {
        // Generate pattern that causes memory allocation complexity
        return "MEMORY:" + "X".repeat(Math.min(size, 1000)) + ":SIZE:" + size;
    }

    private String generateTimingAttackPattern(String secret, int length) {
        // Generate pattern for timing attacks
        StringBuilder attack = new StringBuilder("TIMING:");
        for (int i = 0; i < length; i++) {
            attack.append(secret.charAt(i % secret.length()));
        }
        return attack.toString();
    }

    private String generateWorstCaseSortPattern(int size) {
        // Generate worst-case sorting input (reverse sorted)
        StringBuilder pattern = new StringBuilder("SORT:");
        for (int i = size; i > 0; i--) {
            pattern.append(i % 100).append(",");
        }
        return pattern.toString();
    }

    private String generateComplexGraphPattern(int nodes, int edges) {
        // Generate complex graph pattern
        StringBuilder graph = new StringBuilder("GRAPH:");
        graph.append("NODES:").append(nodes).append(":EDGES:").append(edges);
        // Add complexity by creating dense connections
        for (int i = 0; i < Math.min(nodes, 50); i++) {
            for (int j = 0; j < Math.min(edges / nodes, 10); j++) {
                graph.append(":").append(i).append("->").append((i + j + 1) % nodes);
            }
        }
        return graph.toString();
    }

    private String generateXmlComplexityBomb(int depth) {
        // Generate XML complexity bomb
        StringBuilder xml = new StringBuilder("XML:");
        for (int i = 0; i < depth; i++) {
            xml.append("<entity").append(i).append(">");
            if (i > 0) {
                xml.append("&entity").append(i - 1).append(";");
            }
            xml.append("BOMB");
            xml.append("</entity").append(i).append(">");
        }
        return xml.toString();
    }

    private String generateJsonComplexityAttack(int depth) {
        // Generate JSON complexity attack
        StringBuilder json = new StringBuilder("JSON:{");
        for (int i = 0; i < depth; i++) {
            json.append("\"level").append(i).append("\":{");
        }
        json.append("\"bomb\":\"COMPLEXITY\"");
        for (int i = 0; i < depth; i++) {
            json.append("}");
        }
        json.append("}");
        return json.toString();
    }

    private String generateComplexUrlPattern(String basePattern, int complexity) {
        // Generate complex URL pattern
        StringBuilder url = new StringBuilder(basePattern);
        url.append("?complex=true");
        for (int i = 0; i < complexity; i++) {
            url.append("&param").append(i).append("=value").append(i);
        }
        return url.toString();
    }

    private String generateComplexPatternMatch(String pattern, String target, int length) {
        // Generate complex pattern matching scenario
        StringBuilder complex = new StringBuilder("PATTERN:");
        complex.append(pattern.repeat(length));
        complex.append(":TARGET:");
        complex.append(target);
        return complex.toString();
    }

    private int hashBasedSelection(int arrayLength) {
        return Math.abs(this.hashCode() % arrayLength);
    }

    /**
     * Helper class to cycle through attack types systematically.
     */
    private static class AttackTypeSelector {
        private final int maxTypes;
        private int currentType = 0;

        AttackTypeSelector(int maxTypes) {
            this.maxTypes = maxTypes;
        }

        int nextAttackType() {
            int type = currentType;
            currentType = (currentType + 1) % maxTypes;
            return type;
        }
    }
}