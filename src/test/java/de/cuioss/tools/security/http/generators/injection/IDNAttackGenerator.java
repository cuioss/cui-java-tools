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
 * Generator for Internationalized Domain Name (IDN) attack patterns.
 * 
 * <p><strong>CRITICAL UNICODE SECURITY DATABASE:</strong> This generator contains IDN-specific
 * attack patterns that exploit Unicode homograph vulnerabilities, punycode encoding exploits,
 * and visual domain spoofing techniques. Each pattern uses exact Unicode character sequences
 * that are visually deceptive to humans but distinct to security systems.</p>
 * 
 * <p><strong>QI-6 CONVERSION STATUS:</strong> NOT SUITABLE for dynamic conversion. 
 * IDN/homograph attacks require exact Unicode character pairs where visual similarity
 * is critical (e.g., Cyrillic 'а' vs Latin 'a'). These precise character sequences
 * cannot be algorithmically generated without losing attack effectiveness.</p>
 * 
 * <h3>Unicode Homograph Attack Database</h3>
 * <ul>
 *   <li><strong>Cyrillic homographs:</strong> {@code аpple.com} - Cyrillic 'а' (U+0430) vs Latin 'a' (U+0061)</li>
 *   <li><strong>Punycode exploitation:</strong> {@code xn--pple-43d.com} - ASCII-compatible encoding of Cyrillic domains</li>
 *   <li><strong>Mixed script attacks:</strong> {@code goog1е.com} - Combining Latin and Cyrillic characters</li>
 *   <li><strong>Armenian punctuation:</strong> {@code twitter․com} - Armenian full stop (U+2024) vs period (U+002E)</li>
 *   <li><strong>Right-to-left override:</strong> {@code paypal‮moc.com} - RTL override (U+202E) manipulation</li>
 *   <li><strong>Zero-width exploits:</strong> {@code google​.com} - Zero-width space (U+200B) insertion</li>
 *   <li><strong>Unicode normalization:</strong> {@code café.com} - Composed vs decomposed character forms</li>
 * </ul>
 * 
 * <h3>IDN Attack Mechanics</h3>
 * <ul>
 *   <li><strong>Visual deception:</strong> Characters that look identical but have different Unicode code points</li>
 *   <li><strong>Punycode bypass:</strong> ASCII encoding of international characters bypasses ASCII-only filters</li>
 *   <li><strong>Script mixing:</strong> Combining characters from different writing systems</li>
 *   <li><strong>Invisible characters:</strong> Zero-width and control characters for steganographic attacks</li>
 *   <li><strong>Normalization exploits:</strong> Different Unicode normalizations of the same visual appearance</li>
 * </ul>
 * 
 * <p><strong>PRESERVATION RATIONALE:</strong> IDN attacks depend on exact Unicode character
 * relationships defined by the Unicode Consortium. Each homograph pair (e.g., Cyrillic а vs 
 * Latin a) represents a specific visual vulnerability that must be preserved exactly.
 * Algorithmic generation cannot reproduce these precise linguistic and visual relationships
 * required for effective homograph attack testing.</p>
 * 
 * Implements: Task G-IDN from HTTP verification test generators
 * 
 * @author Claude Code Generator  
 * @since 2.5
 */
public class IDNAttackGenerator implements TypedGenerator<String> {

    private final TypedGenerator<String> idnAttackPatterns = Generators.fixedValues(
            // Homograph attacks - visually similar characters
            "http://аpple.com/../../../etc/passwd",           // Cyrillic 'а' instead of Latin 'a'
            "http://gооgle.com/admin/../../config",          // Cyrillic 'о' instead of Latin 'o'
            "http://miсrosoft.com/../../etc/hosts",          // Cyrillic 'с' instead of Latin 'c'
            "http://аmazon.com/../sensitive/data",           // Cyrillic 'а' instead of Latin 'a'
            "http://fаcebook.com/../../admin/config",        // Cyrillic 'а' instead of Latin 'a'
            "http://раypal.com/../../../etc/passwd",         // Cyrillic 'р' and 'а'
            
            // Punycode exploitation
            "http://xn--pple-43d.com/../../../etc/passwd",   // Punycode for аpple (Cyrillic а)
            "http://xn--e1afmkfd.com/../../config",         // Punycode for пример
            "http://xn--fsq.com/admin/../../etc/hosts",     // Punycode for 中
            "http://xn--nxasmq6b.com/../sensitive",         // Punycode for 测试
            "http://xn--80akhbyknj4f.com/../../admin",      // Punycode for испытание
            "http://xn--wgbl6a.com/../../../etc/passwd",    // Punycode for تست
            
            // Mixed script attacks
            "http://goog1е.com/../../etc/passwd",           // Latin + Cyrillic
            "http://аpp1e.com/admin/../config",             // Cyrillic + Latin + number
            "http://micro5оft.com/../../etc/hosts",         // Mixed Latin/Cyrillic with number
            "http://аmаzоn.com/../sensitive/data",          // Multiple Cyrillic substitutions
            "http://twitter․com/../../admin",               // Armenian full stop instead of period
            "http://instagram‧com/../../../etc/passwd",      // Hyphenation point instead of period
            
            // Unicode normalization bypass
            "http://café.com/../../../etc/passwd",          // é (single character)
            "http://cafe\\u0301.com/../../config",         // e + combining acute accent
            "http://naïve.com/admin/../etc/hosts",          // ï (single character) 
            "http://nai\\u0308ve.com/../../sensitive",     // i + combining diaeresis
            "http://résumé.com/../../../admin",            // Multiple accented characters
            "http://re\\u0301sume\\u0301.com/config",      // Combining characters
            
            // Right-to-left override attacks
            "http://evil‮moc.elgoog.com/../../etc/passwd", // RTL override
            "http://‮moc.elgoog.com/admin/../config",      // RTL override at start
            "http://google‮evil.com/../../etc/hosts",      // RTL override in middle
            "http://legitimate‮.evil.com/../sensitive",     // RTL spoofing
            "http://‭secure‮.fake.com/../../admin",        // LTR + RTL override
            
            // Zero-width and invisible character attacks
            "http://goo​gle.com/../../../etc/passwd",       // Zero-width space
            "http://micro‌soft.com/../../config",          // Zero-width non-joiner
            "http://ama‍zon.com/admin/../etc/hosts",        // Zero-width joiner
            "http://face﻿book.com/../../sensitive",        // Zero-width no-break space
            "http://twit­ter.com/../../../admin",          // Soft hyphen
            "http://insta‌gram.com/../../etc/passwd",      // Zero-width non-joiner
            
            // Bidirectional text attacks
            "http://‮secure-bank.com/../../etc/passwd",    // RTL override
            "http://safe‮-evil.com/admin/../config",       // RTL in middle
            "http://‪legitimate‬.fake.com/../../etc/hosts", // LTR/RTL embedding
            "http://‫trustworthy‬.malicious.com/../sensitive", // RLM/LRM markers
            
            // Unicode confusables
            "http://ｇoogle.com/../../../etc/passwd",       // Full-width Latin
            "http://𝗴𝗼𝗼𝗴𝗹𝗲.com/../../config",              // Mathematical bold
            "http://𝑔𝑜𝑜𝑔𝑙𝑒.com/admin/../etc/hosts",         // Mathematical italic
            "http://𝒈𝒐𝒐𝒈𝒍𝒆.com/../../sensitive",          // Mathematical script
            "http://𝔤𝔬𝔬𝔤𝔩𝔢.com/../../../admin",           // Mathematical fraktur
            
            // Domain with path traversal and IDN
            "http://тest.com/../../../etc/passwd",         // Cyrillic т
            "http://еxample.org/../../admin/config",       // Cyrillic е
            "http://ѕample.net/admin/../etc/hosts",        // Cyrillic ѕ
            "http://dеmo.info/../../sensitive/data",       // Cyrillic е
            "http://tеѕt-site.com/../../../etc/passwd",    // Mixed Cyrillic
            
            // Subdomain IDN attacks
            "http://аdmin.example.com/../../etc/passwd",   // Cyrillic subdomain
            "http://ѕecure.site.com/admin/../config",      // Cyrillic subdomain
            "http://рrivate.domain.org/../../etc/hosts",   // Cyrillic subdomain
            "http://іnternal.test.net/../sensitive",       // Cyrillic і
            
            // Port confusion with IDN
            "http://gооgle.com:8080/../../../etc/passwd",  // Cyrillic о with port
            "http://аpple.com:443/../../admin/config",     // Cyrillic а with SSL port
            "http://miсrosoft.com:80/admin/../etc/hosts",  // Cyrillic с with HTTP port
            
            // Protocol confusion with IDN
            "https://раypal.com/../../../etc/passwd",      // HTTPS with Cyrillic
            "ftp://аmazon.com/../../admin/config",         // FTP with Cyrillic
            "http://fаcebook.com/../etc/hosts",            // HTTP with Cyrillic
            
            // Complex IDN with multiple vulnerabilities
            "http://xn--e1afmkfd.com:8080/../../../etc/passwd", // Punycode + port + path traversal
            "https://goog1е.com/admin/../../config",           // HTTPS + mixed script + traversal
            "http://аpp‌le.com/../sensitive/data",              // Cyrillic + zero-width + traversal
            "http://‮moc.elgoog.com:443/../../admin"           // RTL + port + path traversal
    );

    @Override
    public String next() {
        return idnAttackPatterns.next();
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}