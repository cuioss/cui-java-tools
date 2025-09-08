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
 * Generator for compression bomb attack patterns that test DoS vulnerabilities
 * through excessive resource consumption via compression.
 *
 * <p>Generates 15 different types of compression bomb attacks:
 * <ul>
 *   <li>Basic compression bomb (large expansion ratio)</li>
 *   <li>Nested compression attacks</li>
 *   <li>ZIP bomb patterns</li>
 *   <li>Gzip decompression bombs</li>
 *   <li>Multi-layer compression</li>
 *   <li>Memory exhaustion via expansion</li>
 *   <li>CPU exhaustion via complexity</li>
 *   <li>Recursive compression patterns</li>
 *   <li>Mixed content type bombs</li>
 *   <li>Header-based compression attacks</li>
 *   <li>Parameter-based compression</li>
 *   <li>Cookie compression bombs</li>
 *   <li>Base64 encoded compression</li>
 *   <li>XML/JSON compression bombs</li>
 *   <li>Binary data compression attacks</li>
 * </ul>
 *
 * <p>Each attack type includes multiple specific attack patterns to ensure
 * comprehensive testing of compression bomb detection mechanisms.
 *
 * <p>Based on OWASP guidelines for compression bomb testing and
 * CWE-409: Improper Handling of Highly Compressed Data.
 *
 * @author Security Test Framework
 * @see <a href="https://owasp.org/www-community/attacks/Zip_Bomb">OWASP Zip Bomb</a>
 * @see <a href="https://cwe.mitre.org/data/definitions/409.html">CWE-409</a>
 */
public class CompressionBombAttackGenerator implements TypedGenerator<String> {

    private final AttackTypeSelector attackTypeSelector = new AttackTypeSelector(15);
    private int invocationCounter = 0;

    @Override
    public String next() {
        // Use base pattern that should normally pass validation
        String basePattern = "https://example.com/api/data";
        invocationCounter++;

        return switch (attackTypeSelector.nextAttackType()) {
            case 0 -> createBasicCompressionBomb(basePattern);
            case 1 -> createNestedCompressionAttack(basePattern);
            case 2 -> createZipBombPattern(basePattern);
            case 3 -> createGzipDecompressionBomb(basePattern);
            case 4 -> createMultiLayerCompression(basePattern);
            case 5 -> createMemoryExhaustionBomb(basePattern);
            case 6 -> createCpuExhaustionBomb(basePattern);
            case 7 -> createRecursiveCompressionPattern(basePattern);
            case 8 -> createMixedContentTypeBomb(basePattern);
            case 9 -> createHeaderCompressionAttack(basePattern);
            case 10 -> createParameterCompressionBomb(basePattern);
            case 11 -> createCookieCompressionBomb(basePattern);
            case 12 -> createBase64CompressionBomb(basePattern);
            case 13 -> createXmlJsonCompressionBomb(basePattern);
            case 14 -> createBinaryDataCompressionAttack(basePattern);
            default -> throw new IllegalStateException("Invalid attack type");
        };
    }

    private String createBasicCompressionBomb(String pattern) {
        // Basic compression bomb patterns with realistic expansion indicators
        int attackType = hashBasedSelection(5);
        return switch (attackType) {
            case 0 -> pattern + "?data=" + Generators.letterStrings(800, 1000).next() + "&compress=gzip";
            case 1 -> pattern + "?payload=" + Generators.strings("0", 500, 700).next() + "&encoding=deflate";
            case 2 -> pattern + "?content=" + Generators.strings("X", 600, 800).next() + "&type=compressed";
            case 3 -> pattern + "?bomb=" + Generators.strings("AAAA", 200, 300).next();
            case 4 -> pattern + "?expand=" + Generators.strings("1234", 250, 350).next();
            default -> pattern + "?data=" + Generators.letterStrings(800, 1000).next() + "&compress=gzip";
        };
    }

    private String createNestedCompressionAttack(String pattern) {
        // Nested compression attacks with multiple layers
        String[] nestedAttacks = {
                pattern + "?nested=" + createNestedData("BOMB", 5),
                pattern + "?layers=" + createNestedData("EXPLODE", 7),
                pattern + "?deep=" + createNestedData("ATTACK", 10),
                pattern + "?recursive=" + createNestedData("ZIP", 8),
                pattern + "?compound=" + createNestedData("GZIP", 6),
        };
        return nestedAttacks[hashBasedSelection(nestedAttacks.length)];
    }

    private String createZipBombPattern(String pattern) {
        // ZIP bomb simulation patterns
        String[] zipBombs = {
                pattern + "?zip=" + simulateZipBomb("42.zip", 1000000),
                pattern + "?archive=" + simulateZipBomb("bomb.zip", 2000000),
                pattern + "?package=" + simulateZipBomb("evil.zip", 5000000),
                pattern + "?compressed=" + simulateZipBomb("attack.zip", 10000000),
                pattern + "?payload=" + simulateZipBomb("malicious.zip", 50000000),
        };
        return zipBombs[hashBasedSelection(zipBombs.length)];
    }

    private String createGzipDecompressionBomb(String pattern) {
        // Gzip decompression bomb patterns
        String[] gzipBombs = {
                pattern + "?gzip=" + createGzipBombSignature(1024),
                pattern + "?compressed=" + createGzipBombSignature(2048),
                pattern + "?deflate=" + createGzipBombSignature(4096),
                pattern + "?stream=" + createGzipBombSignature(8192),
                pattern + "?data=" + createGzipBombSignature(16384),
        };
        return gzipBombs[hashBasedSelection(gzipBombs.length)];
    }

    private String createMultiLayerCompression(String pattern) {
        // Multi-layer compression attacks
        String[] multiLayer = {
                pattern + "?multi=LAYER" + createMultiLayerData("1", "2", "3"),
                pattern + "?stack=ZIP" + createMultiLayerData("GZIP", "BZIP2", "LZ4"),
                pattern + "?nested=" + createMultiLayerData("DEFLATE", "LZ4", "ZSTD"),
                pattern + "?compound=" + createMultiLayerData("TAR", "GZ", "XZ"),
                pattern + "?complex=" + createMultiLayerData("RAR", "7Z", "ZIP"),
        };
        return multiLayer[hashBasedSelection(multiLayer.length)];
    }

    private String createMemoryExhaustionBomb(String pattern) {
        // Memory exhaustion through expansion
        String[] memoryBombs = {
                pattern + "?memory=EXPAND" + createExpansionPattern(100000),
                pattern + "?exhaust=EXPAND" + createExpansionPattern(500000),
                pattern + "?overflow=" + createExpansionPattern(1000000),
                pattern + "?oom=" + createExpansionPattern(2000000),
                pattern + "?heap=" + createExpansionPattern(5000000),
        };
        return memoryBombs[hashBasedSelection(memoryBombs.length)];
    }

    private String createCpuExhaustionBomb(String pattern) {
        // CPU exhaustion through complex decompression
        String[] cpuBombs = {
                pattern + "?cpu=COMPLEX" + createComplexityPattern("PATTERN", 100),
                pattern + "?cycles=RECURSIVE" + createComplexityPattern("LOOP", 200),
                pattern + "?intensive=" + createComplexityPattern("HEAVY", 500),
                pattern + "?expensive=" + createComplexityPattern("SLOW", 1000),
                pattern + "?demanding=" + createComplexityPattern("HARD", 2000),
        };
        return cpuBombs[hashBasedSelection(cpuBombs.length)];
    }

    private String createRecursiveCompressionPattern(String pattern) {
        // Recursive compression patterns
        String[] recursivePatterns = {
                pattern + "?recursive=SELF" + createRecursiveData("REF", 10),
                pattern + "?loop=CYCLE" + createRecursiveData("LOOP", 15),
                pattern + "?infinite=" + createRecursiveData("ENDLESS", 20),
                pattern + "?circular=" + createRecursiveData("ROUND", 25),
                pattern + "?spiral=" + createRecursiveData("TWIST", 30),
        };
        return recursivePatterns[hashBasedSelection(recursivePatterns.length)];
    }

    private String createMixedContentTypeBomb(String pattern) {
        // Mixed content type compression bombs with realistic patterns
        int attackType = hashBasedSelection(5);
        return switch (attackType) {
            case 0 -> pattern + "?mixed=text/html;gzip+" + Generators.strings("HTML", 100, 200).next();
            case 1 -> pattern + "?content=application/json;deflate+" + Generators.strings("JSON", 150, 250).next();
            case 2 -> pattern + "?type=image/png;compress+" + Generators.strings("IMAGE", 80, 150).next();
            case 3 -> pattern + "?format=video/mp4;gzip+" + Generators.strings("VIDEO", 60, 120).next();
            case 4 -> pattern + "?media=audio/mpeg;deflate+" + Generators.strings("AUDIO", 100, 180).next();
            default -> pattern + "?mixed=text/html;gzip+" + Generators.strings("HTML", 100, 200).next();
        };
    }

    private String createHeaderCompressionAttack(String pattern) {
        // Header-based compression attacks
        String[] headerAttacks = {
                pattern + "?header=HEADER:" + createCompressedHeader("Accept-Encoding", "gzip,deflate,bomb"),
                pattern + "?accept=HEADER:" + createCompressedHeader("Content-Encoding", "gzip,explode"),
                pattern + "?encoding=" + createCompressedHeader("Transfer-Encoding", "chunked,gzip,bomb"),
                pattern + "?compress=" + createCompressedHeader("Content-Type", "application/zip-bomb"),
                pattern + "?deflate=" + createCompressedHeader("Accept", "*/zip-bomb"),
        };
        return headerAttacks[hashBasedSelection(headerAttacks.length)];
    }

    private String createParameterCompressionBomb(String pattern) {
        // Parameter-based compression bombs
        String[] paramBombs = {
                pattern + "?param=PARAM:" + compressParameter("BOMB", 1000),
                pattern + "?value=PARAM:" + compressParameter("EXPLODE", 2000),
                pattern + "?data=" + compressParameter("ATTACK", 3000),
                pattern + "?payload=" + compressParameter("MALWARE", 4000),
                pattern + "?content=" + compressParameter("VIRUS", 5000),
        };
        return paramBombs[hashBasedSelection(paramBombs.length)];
    }

    private String createCookieCompressionBomb(String pattern) {
        // Cookie-based compression bombs
        String[] cookieBombs = {
                pattern + "?cookie=COOKIE:" + createCompressedCookie("session", "BOMB", 1000),
                pattern + "?auth=COOKIE:" + createCompressedCookie("token", "EXPLODE", 2000),
                pattern + "?user=" + createCompressedCookie("data", "ATTACK", 1500),
                pattern + "?pref=" + createCompressedCookie("settings", "MALICIOUS", 2500),
                pattern + "?tracking=" + createCompressedCookie("id", "DANGEROUS", 3000),
        };
        return cookieBombs[hashBasedSelection(cookieBombs.length)];
    }

    private String createBase64CompressionBomb(String pattern) {
        // Base64 encoded compression bombs
        String[] base64Bombs = {
                pattern + "?b64=BASE64:" + encodeBase64Bomb("COMPRESSED", 1000),
                pattern + "?encoded=BASE64:" + encodeBase64Bomb("BOMB", 2000),
                pattern + "?data=" + encodeBase64Bomb("EXPLOIT", 1500),
                pattern + "?payload=" + encodeBase64Bomb("ATTACK", 2500),
                pattern + "?content=" + encodeBase64Bomb("MALWARE", 3000),
        };
        return base64Bombs[hashBasedSelection(base64Bombs.length)];
    }

    private String createXmlJsonCompressionBomb(String pattern) {
        // XML/JSON compression bombs
        String[] xmlJsonBombs = {
                pattern + "?xml=" + createXmlBomb("ROOT", 100),
                pattern + "?json=JSON:" + createJsonBomb("OBJECT", 200),
                pattern + "?data=" + createXmlBomb("ELEMENT", 150),
                pattern + "?payload=" + createJsonBomb("ARRAY", 250),
                pattern + "?content=" + createXmlBomb("ATTRIBUTE", 300),
        };
        return xmlJsonBombs[hashBasedSelection(xmlJsonBombs.length)];
    }

    private String createBinaryDataCompressionAttack(String pattern) {
        // Binary data compression attacks
        String[] binaryAttacks = {
                pattern + "?binary=BINARY:" + createBinaryBomb(1024),
                pattern + "?blob=BINARY:" + createBinaryBomb(2048),
                pattern + "?raw=" + createBinaryBomb(4096),
                pattern + "?bytes=" + createBinaryBomb(8192),
                pattern + "?stream=" + createBinaryBomb(16384),
        };
        return binaryAttacks[hashBasedSelection(binaryAttacks.length)];
    }

    // Helper methods for creating various compression bomb patterns

    private String generateRepeatedPattern(String base, int repetitions) {
        // Generate realistic repeated patterns within URL limits
        int safeRepetitions = Math.min(repetitions, 200); // Cap at reasonable limit
        return Generators.strings(base, safeRepetitions / base.length(), safeRepetitions / base.length() + 50).next();
    }

    private String createNestedData(String base, int depth) {
        StringBuilder nested = new StringBuilder(base);
        for (int i = 0; i < depth; i++) {
            nested = new StringBuilder("(" + nested + ")");
        }
        return nested.toString();
    }

    private String simulateZipBomb(String filename, int expandedSize) {
        return "ZIP:%s:RATIO:%d:SIZE:%d".formatted(filename, expandedSize / 100, expandedSize);
    }

    private String createGzipBombSignature(int size) {
        return "GZIP:SIGNATURE:SIZE:%d:EXPANSION:%d".formatted(size, size * 1000);
    }

    private String createMultiLayerData(String layer1, String layer2, String layer3) {
        return "%s[%s[%s]]".formatted(layer1, layer2, layer3);
    }

    private String createExpansionPattern(int expansionSize) {
        return "EXPAND:RATIO:1000:TARGET:%d".formatted(expansionSize);
    }

    private String createComplexityPattern(String type, int complexity) {
        return "COMPLEX:%s:LEVEL:%d:CYCLES:%d".formatted(type, complexity, complexity * 10);
    }

    private String createRecursiveData(String base, int depth) {
        if (depth <= 0) return base;
        return base + "[" + createRecursiveData(base, depth - 1) + "]";
    }

    private String createCompressedHeader(String headerName, String value) {
        return "HEADER:%s:VALUE:%s:COMPRESSED".formatted(headerName, value);
    }

    private String compressParameter(String base, int repetitions) {
        // Create compression parameter indicator with realistic size
        return "PARAM:COMPRESSED:%s:%d".formatted(Generators.strings(base, 50, 100).next(), repetitions);
    }

    private String createCompressedCookie(String name, String base, int size) {
        return "COOKIE:%s:COMPRESSED:%s:%d".formatted(name, base, size);
    }

    private String encodeBase64Bomb(String base, int size) {
        return "BASE64:ENCODED:%s:SIZE:%d".formatted(base, size);
    }

    private String createXmlBomb(String element, int depth) {
        StringBuilder xml = new StringBuilder();
        for (int i = 0; i < depth; i++) {
            xml.append("<").append(element).append(i).append(">");
        }
        xml.append("BOMB");
        for (int i = depth - 1; i >= 0; i--) {
            xml.append("</").append(element).append(i).append(">");
        }
        return xml.toString();
    }

    private String createJsonBomb(String type, int size) {
        return "JSON:{\"type\":\"%s\",\"bomb\":\"%s\"}".formatted(type, Generators.strings("X", Math.min(size, 100), Math.min(size, 100)).next());
    }

    private String createBinaryBomb(int size) {
        return "BINARY:SIZE:%d:DATA:%s".formatted(size, Generators.strings("\\x00", Math.min(size / 4, 25), Math.min(size / 4, 25)).next());
    }

    private int hashBasedSelection(int arrayLength) {
        return Math.abs(invocationCounter % arrayLength);
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