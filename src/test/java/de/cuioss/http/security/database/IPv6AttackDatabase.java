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
package de.cuioss.http.security.database;

import de.cuioss.http.security.core.UrlSecurityFailureType;

import java.util.List;

/**
 * Database of IPv6 address attack patterns with comprehensive network protocol security coverage.
 *
 * <p><strong>CRITICAL IPv6 SECURITY DATABASE:</strong> This database contains IPv6-specific
 * attack patterns that exploit network protocol vulnerabilities, parser weaknesses, and
 * IPv6 addressing mechanisms for security bypass attempts.</p>
 *
 * <p>These attacks exploit the complexity of IPv6 address parsing, network access controls
 * that may not properly handle IPv6 formats, and implementation inconsistencies between
 * IPv4 and IPv6 protocol stacks in security systems.</p>
 *
 * <h3>IPv6 Attack Categories</h3>
 * <ul>
 *   <li><strong>IPv4-Mapped Bypasses</strong> - Network access control bypass via IPv6 to IPv4 mapping</li>
 *   <li><strong>Address Parser Confusion</strong> - Exploits IPv6 parsing inconsistencies between libraries</li>
 *   <li><strong>Zone Identifier Injection</strong> - Local network access via scope ID manipulation</li>
 *   <li><strong>Protocol Stack Confusion</strong> - Dual-stack implementation exploitation</li>
 *   <li><strong>URL Encoding Bypasses</strong> - IPv6 bracket handling vulnerabilities</li>
 *   <li><strong>Compression Abuse</strong> - Invalid :: (double colon) usage exploitation</li>
 * </ul>
 *
 * <h3>Network Security Standards</h3>
 * <ul>
 *   <li><strong>RFC 4291</strong> - IP Version 6 Addressing Architecture</li>
 *   <li><strong>RFC 3986</strong> - URI Generic Syntax (IPv6 literals)</li>
 *   <li><strong>RFC 4007</strong> - IPv6 Scoped Address Architecture (Zone IDs)</li>
 *   <li><strong>CWE-20</strong> - Improper Input Validation via IPv6 parsing</li>
 *   <li><strong>CWE-182</strong> - Collapse of Data into Unsafe Value</li>
 * </ul>
 *
 * @since 2.5
 */
public class IPv6AttackDatabase implements AttackDatabase {

    // IPv4-mapped IPv6 localhost bypass attempts
    public static final AttackTestCase IPV4_MAPPED_LOCALHOST_BYPASS = new AttackTestCase(
            "[::ffff:127.0.0.1]/../../../etc/passwd",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "IPv4-mapped IPv6 localhost bypass using [::ffff:127.0.0.1] to access 127.0.0.1 through IPv6 addressing. This exploits network access controls that may whitelist IPv4 localhost but not recognize the IPv6-mapped equivalent, combined with path traversal to access system password files.",
            "INVALID_CHARACTER is expected because despite the IPv6 addressing complexity, the primary attack vector is directory traversal (../../../) to access unauthorized system files outside the web root."
    );

    public static final AttackTestCase IPV4_MAPPED_PRIVATE_NETWORK = new AttackTestCase(
            "[::ffff:192.168.1.1]/../../sensitive",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "IPv4-mapped IPv6 attack targeting private network address 192.168.1.1 through IPv6 representation. This demonstrates how private network access controls can be bypassed when security systems don't properly handle IPv4-mapped IPv6 addresses, allowing lateral movement combined with path traversal.",
            "INVALID_CHARACTER is expected because the core attack mechanism uses directory traversal sequences (../../) to access sensitive files, with IPv6 addressing serving as an access control bypass technique."
    );

    public static final AttackTestCase IPV4_MAPPED_RFC6052 = new AttackTestCase(
            "[64:ff9b::7f00:1]/admin/../system",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "IPv4-mapped IPv6 using RFC 6052 Well-Known Prefix (64:ff9b::/96) to represent 127.0.0.1 in IPv6 format. This exploits the official IPv4-embedded IPv6 address format to bypass localhost restrictions while performing administrative path traversal attacks.",
            "INVALID_CHARACTER is expected because the attack uses administrative directory traversal (admin/../) to access system files, with the IPv6 addressing format serving as a network access control bypass mechanism."
    );

    // IPv6 address confusion patterns
    public static final AttackTestCase IPV6_LOCALHOST_CANONICAL = new AttackTestCase(
            "[::1]/../../etc/passwd",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "Canonical IPv6 localhost address (::1) combined with path traversal. This tests whether security systems properly recognize IPv6 localhost equivalents and enforce the same access restrictions as IPv4 127.0.0.1, attempting to access system password files.",
            "INVALID_CHARACTER is expected due to the directory traversal pattern (../../) designed to escape the web root and access sensitive system files, regardless of the IPv6 addressing format."
    );

    public static final AttackTestCase IPV6_LOCALHOST_EXPANDED = new AttackTestCase(
            "[0:0:0:0:0:0:0:1]/../admin/config",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "Fully expanded IPv6 localhost address without zero compression, testing parser recognition of different IPv6 representation formats. This exploits potential parsing inconsistencies where security systems might recognize compressed (::1) but not expanded forms of the same address.",
            "INVALID_CHARACTER is expected because the attack employs directory traversal (../) to access administrative configuration files outside the intended directory structure."
    );

    public static final AttackTestCase IPV6_LOCALHOST_LEADING_ZEROS = new AttackTestCase(
            "[::0001]/../../etc/hosts",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "IPv6 localhost with leading zeros (::0001) to test normalization handling in security parsers. Different IPv6 implementations may or may not normalize leading zeros consistently, potentially bypassing address-based access controls while performing path traversal.",
            "INVALID_CHARACTER is expected because the primary attack mechanism uses directory traversal sequences to access the system hosts file outside the web application's intended directory scope."
    );

    // Malformed IPv6 addresses for parser confusion
    public static final AttackTestCase MALFORMED_TRIPLE_COLON = new AttackTestCase(
            "[:::1]/admin/config",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "Malformed IPv6 address using three consecutive colons (:::1) to exploit IPv6 parser confusion. While syntactically invalid per RFC 4291, some parsers may handle this inconsistently, potentially bypassing IPv6 address validation while attempting administrative file access.",
            "INVALID_CHARACTER is expected because the malformed IPv6 syntax (:::1) represents an invalid address format that may indicate parser confusion attacks or IPv6 validation bypass attempts."
    );

    public static final AttackTestCase MALFORMED_MULTIPLE_COMPRESSION = new AttackTestCase(
            "[2001:db8:::1]/../../etc/passwd",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "Invalid IPv6 address with multiple compression sequences (2001:db8:::1) violating RFC 4291 rules. This tests parser robustness against malformed addresses that contain more than the allowed single :: compression sequence, combined with path traversal attempts.",
            "INVALID_CHARACTER is expected due to the syntactically invalid IPv6 format containing multiple compression attempts (:::), indicating potential IPv6 parser exploitation or validation bypass techniques."
    );

    public static final AttackTestCase INVALID_HEX_CHARACTERS = new AttackTestCase(
            "[::g]/admin/../config",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "IPv6 address containing invalid hexadecimal character 'g' to test parser error handling. Valid IPv6 addresses only contain hex digits (0-9, a-f), so this tests how security systems handle malformed addresses that might bypass strict validation.",
            "INVALID_CHARACTER is expected because the presence of invalid hexadecimal characters (g) in IPv6 addresses indicates malformed network addressing that may be used to exploit parser weaknesses."
    );

    // IPv6 scope identifier (zone ID) abuse
    public static final AttackTestCase ZONE_ID_INTERFACE_ATTACK = new AttackTestCase(
            "[fe80::1%eth0]/../../etc/passwd",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "IPv6 link-local address with zone identifier (fe80::1%eth0) for interface-specific targeting. Zone IDs specify network interfaces for link-local addresses, and this attack tests whether systems properly validate zone identifiers while performing path traversal to access system files.",
            "INVALID_CHARACTER is expected because despite the IPv6 zone identifier complexity, the core attack uses directory traversal (../../) to access unauthorized system files outside the intended directory structure."
    );

    public static final AttackTestCase ZONE_ID_PATH_INJECTION = new AttackTestCase(
            "[fe80::1%../../../etc]/passwd",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "Advanced zone identifier injection attack where the zone ID itself contains path traversal sequences (../../../etc). This exploits IPv6 zone identifier parsing to inject directory traversal directly into the address format, bypassing traditional path validation.",
            "INVALID_CHARACTER is expected because the zone identifier contains embedded path traversal sequences (../../../etc) designed to escape directory boundaries through IPv6 address parsing manipulation."
    );

    public static final AttackTestCase ZONE_ID_PRIVILEGE_ESCALATION = new AttackTestCase(
            "[::1%admin]/../../config",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "Zone identifier containing privileged term 'admin' combined with path traversal. This tests whether IPv6 zone identifier parsing might be exploited for privilege context injection while maintaining directory traversal attack capabilities.",
            "INVALID_CHARACTER is expected because the attack combines directory traversal (../../) with potential privilege context injection through the IPv6 zone identifier, targeting configuration file access."
    );

    // IPv6 bracket escaping attempts
    public static final AttackTestCase BRACKET_REVERSAL_ATTACK = new AttackTestCase(
            "]2001:db8::1[/../../etc/passwd",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "IPv6 bracket reversal attack with closing bracket before opening bracket. This exploits URL parsing inconsistencies where IPv6 brackets might be processed in unexpected order, potentially bypassing address validation while performing path traversal.",
            "INVALID_CHARACTER is expected because reversed IPv6 brackets (]...[) violate standard IPv6 URL format specifications and may indicate URL parsing exploitation attempts."
    );

    public static final AttackTestCase BRACKET_NESTING_ATTACK = new AttackTestCase(
            "[[2001:db8::1]]/admin/../config",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "IPv6 bracket nesting attack with double bracket enclosure. This tests URL parser handling of nested brackets that violate IPv6 address format standards, potentially causing parser confusion that could bypass address-based security controls.",
            "INVALID_CHARACTER is expected because nested IPv6 brackets ([[...]]) represent malformed URL syntax that may be used to exploit IPv6 address parsing inconsistencies."
    );

    public static final AttackTestCase BRACKET_INJECTION_ATTACK = new AttackTestCase(
            "][::1][/../../etc/passwd",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "Complex bracket injection with multiple bracket pairs in incorrect positions. This advanced attack tests IPv6 URL parser resilience against sophisticated bracket manipulation that might bypass both IPv6 validation and path security controls.",
            "INVALID_CHARACTER is expected due to the malformed bracket sequence (][...][) that violates IPv6 URL syntax and indicates potential parser confusion or injection attacks."
    );

    // IPv6 compression (::) abuse patterns
    public static final AttackTestCase COMPRESSION_OVERFLOW_ATTACK = new AttackTestCase(
            "[::::::1]/../../etc/passwd",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "IPv6 compression overflow using excessive colon sequences (::::::1). While :: can only appear once in valid IPv6, this tests parser handling of compression overflow that might cause parsing errors or bypass validation mechanisms.",
            "INVALID_CHARACTER is expected because excessive compression sequences (::::::1) violate IPv6 addressing standards and indicate potential parser confusion attacks or address validation bypass attempts."
    );

    public static final AttackTestCase COMPRESSION_ISOLATION_ATTACK = new AttackTestCase(
            "[::::::::]/../../../sensitive",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "Pure compression sequence attack using only colon characters. This extreme case tests IPv6 parser robustness against address formats that consist entirely of compression indicators, potentially causing parser failures or unexpected behavior.",
            "INVALID_CHARACTER is expected because address formats consisting only of compression sequences (::::::::) are invalid IPv6 syntax that may be used to exploit parser edge cases."
    );

    public static final AttackTestCase FRAGMENTED_COMPRESSION_ATTACK = new AttackTestCase(
            "[2001:::::::db8::1]/../../etc/hosts",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "Fragmented compression attack mixing valid address parts with excessive compression sequences. This tests parser handling when valid IPv6 components are combined with invalid compression patterns that might bypass address normalization.",
            "INVALID_CHARACTER is expected because the combination of valid IPv6 parts (2001, db8) with invalid compression sequences (:::::::) creates malformed addresses indicating parser exploitation attempts."
    );

    // Port confusion with IPv6
    public static final AttackTestCase IPV6_INVALID_PORT_ATTACK = new AttackTestCase(
            "[::1]:abc/admin/config",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "IPv6 address with invalid port specification using alphabetic characters (abc) instead of numeric port. This tests URL parser handling of malformed port specifications that might bypass port-based access controls or cause parsing errors.",
            "INVALID_CHARACTER is expected because alphabetic port specifications (:abc) violate URL standards and may indicate attempts to exploit port parsing vulnerabilities or bypass port-based security controls."
    );

    public static final AttackTestCase IPV6_NEGATIVE_PORT_ATTACK = new AttackTestCase(
            "[::1]:-80/../../sensitive",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "IPv6 address with negative port number specification. Port numbers must be positive integers (0-65535), so this tests parser handling of invalid negative ports that might cause parsing errors or bypass port validation.",
            "INVALID_CHARACTER is expected because negative port numbers (:-80) are invalid in URL specifications and may indicate attempts to exploit port parsing edge cases or bypass port validation mechanisms."
    );

    public static final AttackTestCase IPV6_PORT_OVERFLOW_ATTACK = new AttackTestCase(
            "[::1]:999999/../../etc/passwd",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "IPv6 address with port number exceeding valid range (999999 > 65535). This tests parser handling of port overflow conditions that might cause integer overflow, parsing errors, or bypass port-based access controls.",
            "INVALID_CHARACTER is expected because port numbers exceeding 65535 (:999999) violate TCP/UDP port specifications and may indicate attempts to exploit port parsing vulnerabilities."
    );

    // Complex IPv6 attack combinations
    public static final AttackTestCase FULL_EXPANSION_TRAVERSAL = new AttackTestCase(
            "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]/../../../../../../etc/passwd",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "Fully expanded IPv6 address with deep path traversal attack. This combines a legitimate-looking IPv6 address format with extensive directory traversal (../../../../../../) to test whether long IPv6 addresses might distract from or obscure path traversal detection.",
            "INVALID_CHARACTER is expected because despite the complex IPv6 addressing, the attack uses extensive directory traversal sequences to access system files outside the intended directory structure."
    );

    public static final AttackTestCase ZONE_EMBEDDED_TRAVERSAL = new AttackTestCase(
            "[fe80::1%../../etc/passwd]/admin",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "Advanced attack embedding path traversal directly within IPv6 zone identifier. This sophisticated technique attempts to inject directory traversal sequences into IPv6 address components, potentially bypassing path validation that only checks URL path segments.",
            "INVALID_CHARACTER is expected because the zone identifier contains embedded directory traversal sequences (../../etc/passwd) designed to escape directory boundaries through IPv6 address parsing manipulation."
    );

    public static final AttackTestCase BRACKET_TRAVERSAL_HYBRID = new AttackTestCase(
            "[2001:db8::1]]/../../../windows/system32/config/sam",
            UrlSecurityFailureType.INVALID_CHARACTER,
            "Hybrid attack combining IPv6 bracket malformation with Windows-specific path traversal. This demonstrates how IPv6 parsing confusion can be combined with OS-specific file system attacks to target Windows system authentication databases.",
            "INVALID_CHARACTER is expected because the attack uses directory traversal patterns (../../../) to access Windows system files, with IPv6 bracket malformation serving as a potential parser confusion technique."
    );

    private static final List<AttackTestCase> ALL_ATTACK_TEST_CASES = List.of(
            IPV4_MAPPED_LOCALHOST_BYPASS,
            IPV4_MAPPED_PRIVATE_NETWORK,
            IPV4_MAPPED_RFC6052,
            IPV6_LOCALHOST_CANONICAL,
            IPV6_LOCALHOST_EXPANDED,
            IPV6_LOCALHOST_LEADING_ZEROS,
            MALFORMED_TRIPLE_COLON,
            MALFORMED_MULTIPLE_COMPRESSION,
            INVALID_HEX_CHARACTERS,
            ZONE_ID_INTERFACE_ATTACK,
            ZONE_ID_PATH_INJECTION,
            ZONE_ID_PRIVILEGE_ESCALATION,
            BRACKET_REVERSAL_ATTACK,
            BRACKET_NESTING_ATTACK,
            BRACKET_INJECTION_ATTACK,
            COMPRESSION_OVERFLOW_ATTACK,
            COMPRESSION_ISOLATION_ATTACK,
            FRAGMENTED_COMPRESSION_ATTACK,
            IPV6_INVALID_PORT_ATTACK,
            IPV6_NEGATIVE_PORT_ATTACK,
            IPV6_PORT_OVERFLOW_ATTACK,
            FULL_EXPANSION_TRAVERSAL,
            ZONE_EMBEDDED_TRAVERSAL,
            BRACKET_TRAVERSAL_HYBRID
    );

    @Override
    public Iterable<AttackTestCase> getAttackTestCases() {
        return ALL_ATTACK_TEST_CASES;
    }

    @Override
    public String getDatabaseName() {
        return "IPv6 Attack Database";
    }

    @Override
    public String getDescription() {
        return "Comprehensive database of IPv6 address attack patterns including IPv4-mapped bypasses, parser confusion, zone identifier injection, bracket escaping, compression abuse, and protocol stack exploitation";
    }

    /**
     * Modern JUnit 5 ArgumentsProvider for seamless parameterized testing without @MethodSource boilerplate.
     *
     * <p><strong>Clean Usage Pattern (2024-2025):</strong></p>
     * <pre>
     * &#64;ParameterizedTest
     * &#64;ArgumentsSource(IPv6AttackDatabase.ArgumentsProvider.class)
     * void shouldRejectIPv6Attacks(AttackTestCase testCase) {
     *     // Test implementation - NO static method or @MethodSource needed!
     * }
     * </pre>
     *
     * @since 2.5
     */
    public static class ArgumentsProvider extends AttackDatabase.ArgumentsProvider<IPv6AttackDatabase> {
        // Implementation inherited - uses reflection to create database instance
    }
}