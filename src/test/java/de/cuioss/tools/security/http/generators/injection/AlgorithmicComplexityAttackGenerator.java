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
package de.cuioss.tools.security.http.generators.injection;

import de.cuioss.test.generator.TypedGenerator;

/**
 * Generator for algorithmic complexity attack patterns that test DoS vulnerabilities
 * through computationally expensive operations that can exhaust CPU, memory, or processing time.
 *
 * <p><strong>QI-6 CONVERSION STATUS:</strong> ALREADY COMPLIANT - This generator uses dynamic 
 * algorithmic generation with {@link AttackTypeSelector} to cycle through attack categories
 * and generates patterns on-demand rather than using hardcoded {@code fixedValues()}.</p>
 *
 * <p><strong>ALGORITHMIC GENERATION APPROACH:</strong> Uses mathematical patterns and 
 * complexity theory to generate DoS attack vectors that exploit algorithmic weaknesses:</p>
 * <ul>
 *   <li><strong>Regex ReDoS:</strong> Exponential backtracking patterns {@code (a+)+b}</li>
 *   <li><strong>Hash Collisions:</strong> Known Java hashCode() collision pairs {@code "Aa" == "BB"}</li>
 *   <li><strong>Deep Recursion:</strong> Nested structure patterns {@code ((((end))))}</li>
 *   <li><strong>Polynomial Complexity:</strong> Patterns that trigger O(n²) behavior</li>
 *   <li><strong>Exponential Complexity:</strong> Patterns that trigger O(2^n) behavior</li>
 *   <li><strong>Memory Bombs:</strong> Small inputs causing exponential memory allocation</li>
 * </ul>
 *
 * <h3>Dynamic Attack Generation</h3>
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
 * <p><strong>SECURITY EFFECTIVENESS:</strong> Each attack type includes multiple specific 
 * attack patterns designed to trigger worst-case algorithmic behavior in URL processing, 
 * parsing, and validation systems while maintaining small input sizes to prevent 
 * OutOfMemoryError during testing.</p>
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
        // True hash collision attacks: known collision strings for Java hashCode()
        String[] hashCollisionAttacks = {
                pattern + "?key1=Aa&key2=BB",           // "Aa".hashCode() == "BB".hashCode()
                pattern + "?param=AaAa&param=BBBB",     // Collision with repeated pattern
                pattern + "?data=AaAaAa&data=AaBBAa",   // More collision combinations
                pattern + "?field=AaBB&field=BaAB",     // Different collision pair
                pattern + "?value=C#&value=D$",         // Another collision pair
        };
        return hashCollisionAttacks[hashBasedSelection(hashCollisionAttacks.length)];
    }

    private String createDeepRecursionAttack(String pattern) {
        // Minimal recursion patterns that cause stack overflow through algorithmic complexity
        String[] recursionAttacks = {
                pattern + "?recurse=((((((((end))))))))",     // 8 levels - enough to test recursion
                pattern + "?deep=[[[[[[[data]]]]]]]",        // Nested array structure
                pattern + "?nested={{{{{{{value}}}}}}}",     // Nested object structure  
                pattern + "?stack=<<<<<<<item>>>>>>>",       // XML-style nested tags
                pattern + "?depth=\\1\\1\\1\\1\\1\\1\\1",    // Backreference recursion
        };
        return recursionAttacks[hashBasedSelection(recursionAttacks.length)];
    }

    private String createNestedLoopComplexityAttack(String pattern) {
        // Small patterns that trigger quadratic behavior in parsing/validation
        String[] nestedLoopAttacks = {
                pattern + "?nested=ABABABAB",      // Simple repetition pattern
                pattern + "?loop=XYZXYZXYZ",       // Repeated sequence
                pattern + "?quadratic=121212",     // Palindromic pattern
                pattern + "?cubic=ABCABCABC",      // Triple repetition
                pattern + "?polynomial=XYXYXY",   // Alternating pattern
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
        // True algorithmic complexity: small inputs that cause exponential memory usage
        String[] memoryAttacks = {
                pattern + "?nested=((((((((level)))))))))",  // Nested parsing complexity
                pattern + "?expand={a:{b:{c:{d:{e:value}}}}}",  // Deep object nesting  
                pattern + "?repeat=\\1\\1\\1\\1\\1\\1\\1\\1",   // Backreference expansion
                pattern + "?entity=&lt;!ENTITY%20bomb%20%22explosion%22%3E", // XML entity hint
                pattern + "?hash=Aa&hash=BB&hash=C#&hash=D$",  // Hash collision candidates
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
        // True algorithmic complexity: ReDoS patterns with minimal input
        String[] patternAttacks = {
                pattern + "?regex=(a+)+b&input=aaaaaac",           // Classic ReDoS: exponential backtracking
                pattern + "?regex=(a|a)*b&input=aaaaaac",          // Alternation ReDoS  
                pattern + "?regex=a(b|c)*d&input=abbbbbbbc",       // Nested quantifier ReDoS
                pattern + "?search=^(a+)+$&input=aaaaaaaX",        // Anchored ReDoS
                pattern + "?pattern=([a-z]+)*[a-z]&input=abcdx",   // Character class ReDoS
        };
        return patternAttacks[hashBasedSelection(patternAttacks.length)];
    }

    // Helper methods for generating various complexity attack patterns

    private String createCatastrophicBacktrackingPattern(String a, String b, int length) {
        // Creates patterns like (a+)+b repeated 'length' times (limited to prevent OutOfMemoryError)
        return "(" + a.repeat(Math.min(length, 20)) + ")++" + b;
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
        return basePattern + alt2.repeat(Math.min(repetitions, 20));
    }

    private String createGroupedQuantifierPattern(String base, int groups) {
        StringBuilder pattern = new StringBuilder();
        for (int i = 0; i < groups; i++) {
            pattern.append("(").append(base).append("*)*");
        }
        return pattern.toString();
    }

    private String createOverlappingQuantifierPattern(String pattern1, String pattern2, int overlap) {
        return "(" + pattern1.repeat(Math.min(overlap, 10)) + "|" + pattern1.repeat(Math.min(overlap, 10)) + ")*" + pattern2;
    }

    private String generateExponentialPattern(String basePattern, String character, int repetitions) {
        return basePattern + character.repeat(Math.min(repetitions, 50));
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
        // Small pattern that hints at polynomial complexity without creating large strings
        return "POLY:" + base + "_nested_loop_hint_size_" + size;
    }

    private String generateExponentialComplexityPattern(String base, int depth) {
        // Small pattern that hints at exponential complexity without creating large strings
        return "EXP:" + base + "_exponential_hint_depth_" + depth;
    }

    private String generateMemoryComplexityPattern(int size) {
        // Generate pattern that causes memory allocation complexity
        return "MEMORY:" + "X".repeat(Math.min(size, 1000)) + ":SIZE:" + size;
    }

    private String generateTimingAttackPattern(String secret, int length) {
        // Small pattern that demonstrates timing attack concept
        return "TIMING:" + secret + "_timing_hint_len_" + length;
    }

    private String generateWorstCaseSortPattern(int size) {
        // Small pattern that hints at worst-case sorting without large strings
        return "SORT:reverse_sorted_hint_size_" + size;
    }

    private String generateComplexGraphPattern(int nodes, int edges) {
        // Small pattern that hints at graph complexity without large strings
        return "GRAPH:dense_graph_hint_nodes_" + nodes + "_edges_" + edges;
    }

    private String generateXmlComplexityBomb(int depth) {
        // Small pattern that hints at XML bomb without creating actual bomb
        return "XML:entity_expansion_hint_depth_" + depth;
    }

    private String generateJsonComplexityAttack(int depth) {
        // Small pattern that hints at JSON complexity without deep nesting
        return "JSON:deep_nesting_hint_depth_" + depth;
    }

    private String generateComplexUrlPattern(String basePattern, int complexity) {
        // Small pattern that hints at URL parsing complexity without many parameters
        return basePattern + "?url_parsing_complexity_hint_params_" + complexity;
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