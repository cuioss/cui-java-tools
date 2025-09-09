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

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.TypedGenerator;

/**
 * Generator for IPv6 address attack patterns.
 * 
 * <p><strong>CRITICAL IPv6 SECURITY DATABASE:</strong> This generator contains IPv6-specific
 * attack patterns that exploit network protocol vulnerabilities, parser weaknesses, and 
 * IPv6 addressing mechanisms for security bypass attempts.</p>
 * 
 * <p><strong>QI-6 CONVERSION STATUS:</strong> NOT SUITABLE for dynamic conversion. 
 * IPv6 attack patterns require exact network address formats, specific encoding sequences,
 * and precise parser confusion techniques. These patterns test critical IPv6 security 
 * vulnerabilities where exact address syntax is essential.</p>
 * 
 * <h3>IPv6 Security Attack Database</h3>
 * <ul>
 *   <li><strong>IPv4-mapped IPv6 bypass:</strong> {@code [::ffff:127.0.0.1]} - Localhost bypass via IPv4 mapping</li>
 *   <li><strong>Address compression abuse:</strong> {@code [::::::1]} - Invalid :: compression exploitation</li>
 *   <li><strong>Scope identifier injection:</strong> {@code [fe80::1%../../../etc]} - Zone ID path traversal</li>
 *   <li><strong>Bracket escaping:</strong> {@code ]2001:db8::1[} - URL bracket manipulation</li>
 *   <li><strong>Parser confusion:</strong> {@code [:::1]} - Malformed address parsing exploitation</li>
 *   <li><strong>Invalid character injection:</strong> {@code [2001:db8::z1]} - Non-hex character exploitation</li>
 *   <li><strong>Multiple compression abuse:</strong> {@code [2001::db8::1]} - Invalid multiple :: usage</li>
 * </ul>
 * 
 * <h3>IPv6-Specific Security Vulnerabilities</h3>
 * <ul>
 *   <li><strong>IPv4-mapped bypasses:</strong> Network access control bypass via IPv6 to IPv4 mapping</li>
 *   <li><strong>Address parser confusion:</strong> Exploits IPv6 parsing inconsistencies between libraries</li>
 *   <li><strong>Zone identifier injection:</strong> Local network access via scope ID manipulation</li>
 *   <li><strong>Protocol stack confusion:</strong> Dual-stack implementation exploitation</li>
 *   <li><strong>URL encoding bypasses:</strong> IPv6 bracket handling vulnerabilities</li>
 * </ul>
 * 
 * <p><strong>PRESERVATION RATIONALE:</strong> IPv6 addressing has strict RFC specifications
 * with specific parsing rules. These attack patterns exploit exact parser edge cases,
 * network protocol vulnerabilities, and IPv6 implementation inconsistencies. Algorithmic
 * generation would lose critical IPv6 address format requirements and network protocol
 * attack effectiveness.</p>
 * 
 * Implements: Task G-IPv6 from HTTP verification test generators
 * 
 * @author Claude Code Generator  
 * @since 2.5
 */
public class IPv6AddressAttackGenerator implements TypedGenerator<String> {

    private final TypedGenerator<String> ipv6AttackPatterns = Generators.fixedValues(
            // IPv4-mapped IPv6 localhost bypass attempts
            "[::ffff:127.0.0.1]/../../../etc/passwd",
            "[::ffff:0.0.0.0]/admin/config",
            "[::ffff:192.168.1.1]/../../sensitive",
            "[::ffff:10.0.0.1]/admin/../config",
            "[::ffff:7f00:1]/../../etc/hosts",
            "[64:ff9b::7f00:1]/admin/../system",

            // IPv6 address confusion patterns
            "[::1]/../../etc/passwd",
            "[0:0:0:0:0:0:0:1]/../admin/config",
            "[::0001]/../../etc/hosts",
            "[2001:db8::1]/admin/../../config",
            "[fe80::1]/../../sensitive/data",
            "[::]/admin/../../../etc/passwd",

            // Malformed IPv6 addresses for parser confusion
            "[:::1]/admin/config",
            "[2001:db8:::1]/../../etc/passwd",
            "[::g]/admin/../config",
            "[2001:zzzz::1]/../../sensitive",
            "[gggg::1]/admin/../../etc/hosts",
            "[2001:xyz::1]/../config",

            // IPv6 scope identifier (zone ID) abuse
            "[fe80::1%eth0]/../../etc/passwd",
            "[::1%lo0]/admin/../config",
            "[2001:db8::1%999]/../../sensitive",
            "[fe80::1%../../../etc]/passwd",
            "[::1%admin]/../../config",
            "[2001:db8::1%../../../../etc]/hosts",

            // IPv6 bracket escaping attempts
            "]2001:db8::1[/../../etc/passwd",
            "[2001:db8::1]]/admin/../../config",
            "[2001:db8::1[/../../sensitive",
            "[[2001:db8::1]]/admin/../config",
            "][::1][/../../etc/passwd",
            "[[][2001:db8::1]]]/admin/config",

            // IPv6 compression (::) abuse patterns
            "[::::::1]/../../etc/passwd",
            "[2001::::::db8]/admin/config",
            "[::::::::]/../../../sensitive",
            "[:::]/../etc/passwd",
            "[::::]/admin/../config",
            "[2001:::::::db8::1]/../../etc/hosts",

            // IPv6 with invalid characters
            "[2001:db8::z1]/../../etc/passwd",
            "[2001:xy8::1]/admin/config",
            "[2001:db8::1z]/../../sensitive",
            "[gggg:hhhh::1]/admin/../config",
            "[2001:!!8::1]/../../etc/hosts",
            "[2001:db@::1]/admin/../../config",

            // Multiple colon patterns
            "[2001::db8::1]/admin/../../etc/passwd",
            "[:::2001:db8::1]/../../config",
            "[2001:db8::1:::]/admin/../sensitive",
            "[::2001::db8::1]/../../etc/hosts",
            "[2001:::db8:::1]/admin/config",

            // Port confusion with IPv6
            "[::1:80]/../../etc/passwd",
            "[2001:db8::1]:abc/admin/config",
            "[::1]:-80/../../sensitive",
            "[2001:db8::1:]/admin/../config",
            "[::1]:999999/../../etc/passwd",

            // IPv6 URL format confusion
            "2001:db8::1]/admin/../../etc/passwd",
            "[2001:db8::1/../../config",
            "http://2001:db8::1]/admin/../config",
            "https://[2001:db8::1/../../sensitive",
            "ftp://]2001:db8::1[/admin/config",

            // IPv6 with path traversal combinations
            "http://[2001:db8::1]/../../../etc/passwd",
            "https://[::1]/admin/../../config.xml",
            "[fe80::1]/uploads/../../../etc/shadow",
            "http://[::ffff:10.0.0.1]/files/..\\..\\windows\\win.ini",
            "[2001:db8::1]/api/../../../sensitive/data",

            // IPv6 localhost variations with attacks
            "[::1]/../../etc/passwd",
            "[0000:0000:0000:0000:0000:0000:0000:0001]/admin/../config",
            "[::ffff:127.0.0.1]/../../etc/hosts",
            "[::127.0.0.1]/admin/../../sensitive",
            "[::1:0:0:1]/../../etc/passwd",

            // Complex IPv6 attack combinations
            "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]/../../../../../../etc/passwd",
            "[fe80::1%../../etc/passwd]/admin",
            "[::ffff:0:127.0.0.1]/admin/../../../etc/shadow",
            "[2001:db8::1]]/../../../windows/system32/config/sam"
    );

    @Override
    public String next() {
        return ipv6AttackPatterns.next();
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}