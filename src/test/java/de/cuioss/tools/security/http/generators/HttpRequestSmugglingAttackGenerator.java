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
 * T16: HTTP Request Smuggling Attack Generator
 * 
 * <p>
 * This generator creates comprehensive HTTP request smuggling attack patterns that exploit
 * discrepancies in how front-end and back-end servers parse HTTP requests. HTTP request
 * smuggling is a critical vulnerability that can lead to request hijacking, cache poisoning,
 * authentication bypass, and access to other users' requests by sending ambiguous HTTP
 * requests that are interpreted differently by different servers in the chain.
 * </p>
 * 
 * <h3>Attack Types Generated</h3>
 * <ul>
 *   <li>CL.TE Smuggling - Content-Length vs Transfer-Encoding conflicts</li>
 *   <li>TE.CL Smuggling - Transfer-Encoding vs Content-Length conflicts</li>
 *   <li>TE.TE Smuggling - Dual Transfer-Encoding header confusion</li>
 *   <li>CL.CL Smuggling - Duplicate Content-Length header attacks</li>
 *   <li>HTTP/2 Downgrade Smuggling - Protocol version downgrade attacks</li>
 *   <li>Pipeline Poisoning - Request pipeline contamination</li>
 *   <li>Cache Deception - Cache poisoning via smuggled requests</li>
 *   <li>Authentication Bypass - Session hijacking through smuggling</li>
 *   <li>Header Manipulation - Request header modification attacks</li>
 *   <li>Method Override Smuggling - HTTP method manipulation</li>
 *   <li>URL Rewriting Attacks - Request URL modification via smuggling</li>
 *   <li>Request Hijacking - Capturing other users' requests</li>
 *   <li>Response Queue Poisoning - Response desynchronization attacks</li>
 *   <li>WebSocket Upgrade Smuggling - Protocol upgrade manipulation</li>
 *   <li>Chunked Encoding Bypass - Transfer-encoding chunk manipulation</li>
 * </ul>
 * 
 * <h3>Security Standards Compliance</h3>
 * <ul>
 *   <li>OWASP Top 10: A03:2021 – Injection</li>
 *   <li>CWE-444: Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling')</li>
 *   <li>CWE-436: Interpretation Conflict</li>
 *   <li>RFC 7230: HTTP/1.1 Message Syntax and Routing</li>
 *   <li>RFC 9112: HTTP/1.1 Specification</li>
 * </ul>
 * 
 * @see de.cuioss.tools.security.http.tests.HttpRequestSmugglingAttackTest
 * @author Generated for HTTP Security Validation (T16)
 * @version 1.0.0
 */
public class HttpRequestSmugglingAttackGenerator implements TypedGenerator<String> {

    private static final String[] BASE_URLS = {
            "http://example.com/api/data",
            "https://app.domain.com/process",
            "http://localhost:8080/request",
            "https://secure.site.org/proxy/forward",
            "http://test.example.com/gateway"
    };

    @Override
    public String next() {
        String baseUrl = BASE_URLS[hashBasedSelection(BASE_URLS.length)];

        return switch (hashBasedSelection(15)) {
            case 0 -> createClTeSmuggling(baseUrl);
            case 1 -> createTeClSmuggling(baseUrl);
            case 2 -> createTeTeSmuggling(baseUrl);
            case 3 -> createClClSmuggling(baseUrl);
            case 4 -> createHttp2DowngradeSmuggling(baseUrl);
            case 5 -> createPipelinePoisoning(baseUrl);
            case 6 -> createCacheDeception(baseUrl);
            case 7 -> createAuthenticationBypass(baseUrl);
            case 8 -> createHeaderManipulation(baseUrl);
            case 9 -> createMethodOverrideSmuggling(baseUrl);
            case 10 -> createUrlRewritingAttack(baseUrl);
            case 11 -> createRequestHijacking(baseUrl);
            case 12 -> createResponseQueuePoisoning(baseUrl);
            case 13 -> createWebSocketUpgradeSmuggling(baseUrl);
            case 14 -> createChunkedEncodingBypass(baseUrl);
            default -> createClTeSmuggling(baseUrl);
        };
    }

    private String createClTeSmuggling(String pattern) {
        String[] clTeAttacks = {
                pattern + "?data=test%0d%0aContent-Length: 6%0d%0aTransfer-Encoding: chunked%0d%0a%0d%0a0%0d%0a%0d%0aG",
                pattern + "?param=value%0d%0aContent-Length: 4%0d%0aTransfer-Encoding: chunked%0d%0a%0d%0a5c%0d%0aGET /admin HTTP/1.1",
                pattern + "?test=data%0d%0aContent-Length: 13%0d%0aTransfer-Encoding: chunked%0d%0a%0d%0a0%0d%0a%0d%0aGET /secret",
                pattern + "?input=normal%0d%0aContent-Length: 15%0d%0aTransfer-Encoding: chunked%0d%0a%0d%0a0%0d%0a%0d%0aPOST /backdoor",
                pattern + "?payload=cl.te%0d%0aContent-Length: 8%0d%0aTransfer-Encoding: chunked%0d%0a%0d%0a0%0d%0a%0d%0aSMUGGLE",
                pattern + "?attack=smuggle%0d%0aContent-Length: 44%0d%0aTransfer-Encoding: chunked%0d%0a%0d%0a0%0d%0a%0d%0aGET /admin HTTP/1.1%0d%0aHost: vulnerable-website.com",
                pattern + "?method=get%0d%0aContent-Length: 30%0d%0aTransfer-Encoding: chunked%0d%0a%0d%0a0%0d%0a%0d%0aDELETE /admin/users HTTP/1.1"
        };
        return clTeAttacks[hashBasedSelection(clTeAttacks.length)];
    }

    private String createTeClSmuggling(String pattern) {
        String[] teClAttacks = {
                pattern + "?data=test%0d%0aTransfer-Encoding: chunked%0d%0aContent-Length: 4%0d%0a%0d%0a5c%0d%0aGET /admin HTTP/1.1%0d%0a0%0d%0a%0d%0a",
                pattern + "?param=value%0d%0aTransfer-Encoding: chunked%0d%0aContent-Length: 6%0d%0a%0d%0a0%0d%0a%0d%0aG",
                pattern + "?test=smuggle%0d%0aTransfer-Encoding: chunked%0d%0aContent-Length: 13%0d%0a%0d%0a56%0d%0aGET /secret HTTP/1.1%0d%0aHost: internal%0d%0a%0d%0a0%0d%0a%0d%0a",
                pattern + "?input=normal%0d%0aTransfer-Encoding: chunked%0d%0aContent-Length: 15%0d%0a%0d%0a2a%0d%0aPOST /backdoor HTTP/1.1%0d%0aContent-Length: 15%0d%0a%0d%0a0%0d%0a%0d%0a",
                pattern + "?payload=te.cl%0d%0aTransfer-Encoding: chunked%0d%0aContent-Length: 8%0d%0a%0d%0a23%0d%0aGET /admin/delete?user=victim%0d%0a0%0d%0a%0d%0a",
                pattern + "?attack=request%0d%0aTransfer-Encoding: chunked%0d%0aContent-Length: 44%0d%0a%0d%0a71%0d%0aPOST /admin/users HTTP/1.1%0d%0aHost: vulnerable%0d%0aContent-Length: 15%0d%0a%0d%0ax=1%0d%0a0%0d%0a%0d%0a",
                pattern + "?method=post%0d%0aTransfer-Encoding: chunked%0d%0aContent-Length: 30%0d%0a%0d%0a3c%0d%0aDELETE /admin/users/victim HTTP/1.1%0d%0aHost: internal-admin%0d%0a%0d%0a0%0d%0a%0d%0a"
        };
        return teClAttacks[hashBasedSelection(teClAttacks.length)];
    }

    private String createTeTeSmuggling(String pattern) {
        String[] teTeAttacks = {
                pattern + "?data=test%0d%0aTransfer-Encoding: chunked%0d%0aTransfer-Encoding: identity%0d%0a%0d%0a5c%0d%0aGET /admin HTTP/1.1",
                pattern + "?param=value%0d%0aTransfer-Encoding: chunked%0d%0aTransfer-encoding: chunked%0d%0a%0d%0a0%0d%0a%0d%0aSMUGGLE",
                pattern + "?test=smuggle%0d%0aTransfer-Encoding: xchunked%0d%0aTransfer-Encoding: chunked%0d%0a%0d%0a23%0d%0aGET /secret HTTP/1.1%0d%0a0%0d%0a%0d%0a",
                pattern + "?input=normal%0d%0aTransfer-Encoding: chunked%0d%0aTransfer-Encoding: x%0d%0a%0d%0a2a%0d%0aPOST /backdoor HTTP/1.1%0d%0a0%0d%0a%0d%0a",
                pattern + "?payload=te.te%0d%0aTransfer-Encoding: chunked, identity%0d%0aTransfer-Encoding: identity%0d%0a%0d%0a5c%0d%0aGET /admin/delete",
                pattern + "?attack=double%0d%0aTransfer-Encoding: identity%0d%0aTransfer-Encoding: chunked%0d%0a%0d%0a71%0d%0aPOST /admin/users HTTP/1.1%0d%0a0%0d%0a%0d%0a",
                pattern + "?method=multiple%0d%0aTransfer-Encoding: chunked%0d%0aTransfer-Encoding:%20chunked%0d%0a%0d%0a3c%0d%0aDELETE /users HTTP/1.1%0d%0a0%0d%0a%0d%0a"
        };
        return teTeAttacks[hashBasedSelection(teTeAttacks.length)];
    }

    private String createClClSmuggling(String pattern) {
        String[] clClAttacks = {
                pattern + "?data=test%0d%0aContent-Length: 6%0d%0aContent-Length: 0%0d%0a%0d%0aGET /admin HTTP/1.1",
                pattern + "?param=value%0d%0aContent-Length: 13%0d%0aContent-Length: 7%0d%0a%0d%0aSMUGGLE REQUEST",
                pattern + "?test=smuggle%0d%0aContent-Length: 0%0d%0aContent-Length: 44%0d%0a%0d%0aGET /secret HTTP/1.1%0d%0aHost: vulnerable-website.com",
                pattern + "?input=normal%0d%0aContent-Length: 15%0d%0aContent-Length: 25%0d%0a%0d%0aPOST /backdoor HTTP/1.1%0d%0aContent-Length: 15",
                pattern + "?payload=cl.cl%0d%0aContent-Length: 8%0d%0aContent-Length: 30%0d%0a%0d%0aGET /admin/delete?user=victim",
                pattern + "?attack=duplicate%0d%0aContent-Length: 44%0d%0aContent-Length: 6%0d%0a%0d%0aPOST /admin/users HTTP/1.1%0d%0ax=1",
                pattern + "?method=conflict%0d%0aContent-Length: 30%0d%0aContent-Length: 60%0d%0a%0d%0aDELETE /admin/users/victim HTTP/1.1%0d%0aHost: internal"
        };
        return clClAttacks[hashBasedSelection(clClAttacks.length)];
    }

    private String createHttp2DowngradeSmuggling(String pattern) {
        String[] http2Attacks = {
                pattern + "?data=test%0d%0aHTTP2-Settings: AAMAAABkAAQAAgAAAAA%0d%0aUpgrade: h2c%0d%0aConnection: Upgrade, HTTP2-Settings%0d%0aContent-Length: 0",
                pattern + "?param=h2%0d%0aConnection: Upgrade%0d%0aUpgrade: h2c%0d%0aHTTP2-Settings: smuggle%0d%0aContent-Length: 35%0d%0a%0d%0aGET /admin HTTP/1.1",
                pattern + "?test=downgrade%0d%0aPRI * HTTP/2.0%0d%0a%0d%0aSM%0d%0a%0d%0aGET /secret HTTP/1.1%0d%0aHost: internal",
                pattern + "?input=protocol%0d%0aHTTP2-Settings: smuggled%0d%0aUpgrade: h2c%0d%0aConnection: HTTP2-Settings%0d%0aContent-Length: 25",
                pattern + "?payload=h2smuggle%0d%0aConnection: close, Upgrade%0d%0aUpgrade: h2c%0d%0aHTTP2-Settings: AAMAAABkAAQAAgAAAAA%0d%0aContent-Length: 44",
                pattern + "?attack=version%0d%0aPRI * HTTP/2.0%0d%0a%0d%0aSM%0d%0a%0d%0aPOST /admin/users HTTP/1.1%0d%0aHost: vulnerable",
                pattern + "?method=upgrade%0d%0aUpgrade: h2c%0d%0aConnection: Upgrade%0d%0aHTTP2-Settings: exploit%0d%0aContent-Length: 30"
        };
        return http2Attacks[hashBasedSelection(http2Attacks.length)];
    }

    private String createPipelinePoisoning(String pattern) {
        String[] pipelineAttacks = {
                pattern + "?data=test%0d%0aConnection: keep-alive%0d%0aContent-Length: 44%0d%0a%0d%0aGET /admin HTTP/1.1%0d%0aHost: vulnerable-website.com%0d%0a%0d%0a",
                pattern + "?param=pipeline%0d%0aConnection: keep-alive%0d%0aContent-Length: 0%0d%0a%0d%0aPOST /admin/users HTTP/1.1%0d%0aContent-Length: 15",
                pattern + "?test=poison%0d%0aConnection: keep-alive%0d%0aContent-Length: 56%0d%0a%0d%0aGET /secret HTTP/1.1%0d%0aHost: internal%0d%0aAuthorization: Bearer token",
                pattern + "?input=keep%0d%0aConnection: keep-alive%0d%0aContent-Length: 25%0d%0a%0d%0aDELETE /backdoor HTTP/1.1%0d%0aHost: admin",
                pattern + "?payload=persist%0d%0aConnection: keep-alive%0d%0aContent-Length: 71%0d%0a%0d%0aPOST /admin/delete HTTP/1.1%0d%0aHost: vulnerable%0d%0aContent-Length: 15%0d%0a%0d%0ax=1",
                pattern + "?attack=queue%0d%0aConnection: keep-alive%0d%0aContent-Length: 35%0d%0a%0d%0aGET /admin/users/victim HTTP/1.1%0d%0aHost: internal-admin",
                pattern + "?method=persistent%0d%0aConnection: keep-alive%0d%0aContent-Length: 60%0d%0a%0d%0aPUT /admin/settings HTTP/1.1%0d%0aHost: vulnerable%0d%0aContent-Length: 20"
        };
        return pipelineAttacks[hashBasedSelection(pipelineAttacks.length)];
    }

    private String createCacheDeception(String pattern) {
        String[] cacheAttacks = {
                pattern + "?data=test%0d%0aCache-Control: max-age=3600%0d%0aContent-Length: 44%0d%0a%0d%0aGET /admin/sensitive HTTP/1.1%0d%0aHost: cache-target",
                pattern + "?param=cache%0d%0aVary: User-Agent%0d%0aContent-Length: 0%0d%0a%0d%0aPOST /admin/users HTTP/1.1%0d%0aAuthorization: Bearer stolen",
                pattern + "?test=deception%0d%0aCache-Control: public%0d%0aContent-Length: 56%0d%0a%0d%0aGET /secret.json HTTP/1.1%0d%0aHost: api%0d%0aX-API-Key: secret",
                pattern + "?input=poison%0d%0aExpires: Wed, 21 Oct 2025 07:28:00 GMT%0d%0aContent-Length: 25%0d%0a%0d%0aDELETE /cache HTTP/1.1%0d%0aHost: admin",
                pattern + "?payload=store%0d%0aCache-Control: max-age=31536000%0d%0aContent-Length: 71%0d%0a%0d%0aPOST /admin/config HTTP/1.1%0d%0aHost: vulnerable%0d%0aContent-Length: 15",
                pattern + "?attack=cdn%0d%0aVary: Authorization%0d%0aContent-Length: 35%0d%0a%0d%0aGET /admin/secrets HTTP/1.1%0d%0aAuthorization: Basic admin:pass",
                pattern + "?method=edge%0d%0aCache-Control: public, max-age=86400%0d%0aContent-Length: 60%0d%0a%0d%0aPUT /admin/cache HTTP/1.1%0d%0aHost: edge-cache"
        };
        return cacheAttacks[hashBasedSelection(cacheAttacks.length)];
    }

    private String createAuthenticationBypass(String pattern) {
        String[] authBypassAttacks = {
                pattern + "?data=test%0d%0aAuthorization: Bearer hijacked%0d%0aContent-Length: 44%0d%0a%0d%0aGET /admin/users HTTP/1.1%0d%0aHost: admin-panel",
                pattern + "?param=auth%0d%0aX-Forwarded-User: admin%0d%0aContent-Length: 0%0d%0a%0d%0aPOST /protected HTTP/1.1%0d%0aAuthorization: Bearer victim-token",
                pattern + "?test=bypass%0d%0aX-Remote-User: root%0d%0aContent-Length: 56%0d%0a%0d%0aGET /admin/secrets HTTP/1.1%0d%0aHost: internal%0d%0aSession-Id: stolen",
                pattern + "?input=session%0d%0aCookie: session=admin-session%0d%0aContent-Length: 25%0d%0a%0d%0aDELETE /users/victim HTTP/1.1%0d%0aHost: app",
                pattern + "?payload=hijack%0d%0aX-Forwarded-For: 127.0.0.1%0d%0aContent-Length: 71%0d%0a%0d%0aPOST /admin/elevate HTTP/1.1%0d%0aHost: vulnerable%0d%0aContent-Length: 15",
                pattern + "?attack=identity%0d%0aX-User-Role: administrator%0d%0aContent-Length: 35%0d%0a%0d%0aGET /admin/config HTTP/1.1%0d%0aX-Internal-User: admin",
                pattern + "?method=spoof%0d%0aX-Original-URL: /admin%0d%0aContent-Length: 60%0d%0a%0d%0aPUT /admin/users HTTP/1.1%0d%0aHost: spoofed%0d%0aAuthorization: spoofed"
        };
        return authBypassAttacks[hashBasedSelection(authBypassAttacks.length)];
    }

    private String createHeaderManipulation(String pattern) {
        String[] headerAttacks = {
                pattern + "?data=test%0d%0aX-Forwarded-Proto: https%0d%0aContent-Length: 44%0d%0a%0d%0aGET /admin HTTP/1.1%0d%0aX-Forwarded-Proto: http",
                pattern + "?param=header%0d%0aHost: evil.com%0d%0aContent-Length: 0%0d%0a%0d%0aPOST /webhook HTTP/1.1%0d%0aHost: legitimate.com",
                pattern + "?test=inject%0d%0aX-Forwarded-Host: attacker.com%0d%0aContent-Length: 56%0d%0a%0d%0aGET /password-reset HTTP/1.1%0d%0aHost: victim.com",
                pattern + "?input=modify%0d%0aX-Original-IP: 192.168.1.1%0d%0aContent-Length: 25%0d%0a%0d%0aDELETE /admin HTTP/1.1%0d%0aX-Real-IP: attacker",
                pattern + "?payload=override%0d%0aX-HTTP-Method-Override: DELETE%0d%0aContent-Length: 71%0d%0a%0d%0aPOST /users HTTP/1.1%0d%0aHost: vulnerable",
                pattern + "?attack=replace%0d%0aReferer: http://admin.internal%0d%0aContent-Length: 35%0d%0a%0d%0aGET /internal/api HTTP/1.1%0d%0aReferer: http://evil.com",
                pattern + "?method=swap%0d%0aUser-Agent: AdminBot/1.0%0d%0aContent-Length: 60%0d%0a%0d%0aPUT /config HTTP/1.1%0d%0aUser-Agent: AttackerBot/2.0"
        };
        return headerAttacks[hashBasedSelection(headerAttacks.length)];
    }

    private String createMethodOverrideSmuggling(String pattern) {
        String[] methodOverrideAttacks = {
                pattern + "?data=test%0d%0aX-HTTP-Method-Override: DELETE%0d%0aContent-Length: 44%0d%0a%0d%0aPOST /admin/users HTTP/1.1%0d%0aHost: vulnerable",
                pattern + "?param=override%0d%0aX-HTTP-Method: PUT%0d%0aContent-Length: 0%0d%0a%0d%0aGET /admin/config HTTP/1.1%0d%0aX-Method-Override: PATCH",
                pattern + "?test=method%0d%0aX-Method-Override: DELETE%0d%0aContent-Length: 56%0d%0a%0d%0aPOST /users/victim HTTP/1.1%0d%0aHost: app%0d%0aContent-Length: 0",
                pattern + "?input=verb%0d%0a_method: PUT%0d%0aContent-Length: 25%0d%0a%0d%0aGET /admin/settings HTTP/1.1%0d%0a_method: DELETE",
                pattern + "?payload=tunnel%0d%0aX-HTTP-Method-Override: PATCH%0d%0aContent-Length: 71%0d%0a%0d%0aPOST /admin/users HTTP/1.1%0d%0aHost: vulnerable%0d%0a_method: DELETE",
                pattern + "?attack=disguise%0d%0aX-Method: DELETE%0d%0aContent-Length: 35%0d%0a%0d%0aGET /users HTTP/1.1%0d%0aX-HTTP-Method-Override: DELETE",
                pattern + "?method=hidden%0d%0a_method: PATCH%0d%0aContent-Length: 60%0d%0a%0d%0aPOST /admin/config HTTP/1.1%0d%0aX-Method-Override: PUT"
        };
        return methodOverrideAttacks[hashBasedSelection(methodOverrideAttacks.length)];
    }

    private String createUrlRewritingAttack(String pattern) {
        String[] urlRewriteAttacks = {
                pattern + "?data=test%0d%0aX-Original-URL: /admin/users%0d%0aContent-Length: 44%0d%0a%0d%0aGET /public HTTP/1.1%0d%0aHost: vulnerable",
                pattern + "?param=rewrite%0d%0aX-Rewrite-URL: /admin/secrets%0d%0aContent-Length: 0%0d%0a%0d%0aPOST /allowed HTTP/1.1%0d%0aX-Original-URL: /forbidden",
                pattern + "?test=url%0d%0aX-Original-URI: /admin/config%0d%0aContent-Length: 56%0d%0a%0d%0aGET /public/info HTTP/1.1%0d%0aHost: app%0d%0aX-Rewrite-URL: /admin",
                pattern + "?input=path%0d%0aX-Forwarded-URI: /admin/delete%0d%0aContent-Length: 25%0d%0a%0d%0aDELETE /safe HTTP/1.1%0d%0aX-Original-URI: /admin",
                pattern + "?payload=redirect%0d%0aX-Original-URL: /admin/elevate%0d%0aContent-Length: 71%0d%0a%0d%0aPOST /public HTTP/1.1%0d%0aHost: vulnerable%0d%0aX-Rewrite-URL: /admin",
                pattern + "?attack=route%0d%0aX-Forwarded-Path: /admin/users%0d%0aContent-Length: 35%0d%0a%0d%0aGET /normal HTTP/1.1%0d%0aX-Original-URL: /admin/delete",
                pattern + "?method=proxy%0d%0aX-Proxy-URL: /admin/config%0d%0aContent-Length: 60%0d%0a%0d%0aPUT /public/data HTTP/1.1%0d%0aX-Forwarded-URI: /admin"
        };
        return urlRewriteAttacks[hashBasedSelection(urlRewriteAttacks.length)];
    }

    private String createRequestHijacking(String pattern) {
        String[] hijackingAttacks = {
                pattern + "?data=test%0d%0aContent-Length: 0%0d%0a%0d%0aGET /victim-request HTTP/1.1%0d%0aHost: hijack-target%0d%0aAuthorization: Bearer victim-token",
                pattern + "?param=hijack%0d%0aContent-Length: 5%0d%0a%0d%0aX=1POST /capture HTTP/1.1%0d%0aHost: attacker.com%0d%0aContent-Length: 100",
                pattern + "?test=capture%0d%0aContent-Length: 15%0d%0a%0d%0aSMUGGLED_REQUESTGET /sensitive HTTP/1.1%0d%0aHost: internal%0d%0aSession-Id: victim",
                pattern + "?input=steal%0d%0aContent-Length: 30%0d%0a%0d%0aHIJACK_PAYLOAD_REQUESTPOST /admin HTTP/1.1%0d%0aHost: target%0d%0aAuthorization: Bearer stolen",
                pattern + "?payload=intercept%0d%0aContent-Length: 44%0d%0a%0d%0aINTERCEPTED_USER_REQUESTGET /profile HTTP/1.1%0d%0aHost: app%0d%0aCookie: session=victim",
                pattern + "?attack=poison%0d%0aContent-Length: 60%0d%0a%0d%0aPOISONED_REQUEST_QUEUEGET /admin/users HTTP/1.1%0d%0aHost: admin%0d%0aX-API-Key: secret",
                pattern + "?method=queue%0d%0aContent-Length: 35%0d%0a%0d%0aQUEUE_POISONING_ATTACKDELETE /users HTTP/1.1%0d%0aHost: api%0d%0aAuthorization: admin"
        };
        return hijackingAttacks[hashBasedSelection(hijackingAttacks.length)];
    }

    private String createResponseQueuePoisoning(String pattern) {
        String[] queuePoisonAttacks = {
                pattern + "?data=test%0d%0aContent-Length: 0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html%0d%0aContent-Length: 25%0d%0a%0d%0a<h1>Poisoned Response</h1>",
                pattern + "?param=poison%0d%0aContent-Length: 5%0d%0a%0d%0aX=1HTTP/1.1 302 Found%0d%0aLocation: http://evil.com%0d%0aContent-Length: 0",
                pattern + "?test=queue%0d%0aContent-Length: 15%0d%0a%0d%0aSMUGGLED_RESPONSEHTTP/1.1 401 Unauthorized%0d%0aWWW-Authenticate: Basic realm=\"admin\"",
                pattern + "?input=desync%0d%0aContent-Length: 30%0d%0a%0d%0aFAKE_RESPONSE_HEADERHTTP/1.1 500 Internal Server Error%0d%0aContent-Type: text/plain",
                pattern + "?payload=corrupt%0d%0aContent-Length: 44%0d%0a%0d%0aRESPONSE_QUEUE_CORRUPTIONHTTP/1.1 403 Forbidden%0d%0aContent-Length: 15%0d%0a%0d%0aAccess Denied",
                pattern + "?attack=desynchronize%0d%0aContent-Length: 60%0d%0a%0d%0aDESYNC_ATTACK_RESPONSEHTTP/1.1 200 OK%0d%0aSet-Cookie: admin=true%0d%0aContent-Length: 10",
                pattern + "?method=mismatch%0d%0aContent-Length: 35%0d%0a%0d%0aRESPONSE_MISMATCH_ATTACKHTTP/1.1 301 Moved%0d%0aLocation: javascript:alert(1)"
        };
        return queuePoisonAttacks[hashBasedSelection(queuePoisonAttacks.length)];
    }

    private String createWebSocketUpgradeSmuggling(String pattern) {
        String[] websocketAttacks = {
                pattern + "?data=test%0d%0aUpgrade: websocket%0d%0aConnection: Upgrade%0d%0aContent-Length: 44%0d%0a%0d%0aGET /admin HTTP/1.1%0d%0aHost: websocket-target",
                pattern + "?param=ws%0d%0aSec-WebSocket-Key: smuggled%0d%0aUpgrade: websocket%0d%0aContent-Length: 0%0d%0a%0d%0aPOST /admin/users HTTP/1.1",
                pattern + "?test=websocket%0d%0aConnection: keep-alive, Upgrade%0d%0aUpgrade: websocket%0d%0aContent-Length: 56%0d%0a%0d%0aGET /sensitive HTTP/1.1%0d%0aHost: internal",
                pattern + "?input=protocol%0d%0aSec-WebSocket-Protocol: smuggle%0d%0aUpgrade: websocket%0d%0aContent-Length: 25%0d%0a%0d%0aDELETE /admin HTTP/1.1",
                pattern + "?payload=upgrade%0d%0aConnection: Upgrade%0d%0aSec-WebSocket-Version: 13%0d%0aContent-Length: 71%0d%0a%0d%0aPOST /admin/config HTTP/1.1%0d%0aHost: vulnerable",
                pattern + "?attack=handshake%0d%0aSec-WebSocket-Extensions: smuggle%0d%0aUpgrade: websocket%0d%0aContent-Length: 35%0d%0a%0d%0aGET /admin/secrets HTTP/1.1",
                pattern + "?method=switch%0d%0aConnection: Upgrade%0d%0aUpgrade: websocket%0d%0aContent-Length: 60%0d%0a%0d%0aPUT /admin/websocket HTTP/1.1%0d%0aHost: target"
        };
        return websocketAttacks[hashBasedSelection(websocketAttacks.length)];
    }

    private String createChunkedEncodingBypass(String pattern) {
        String[] chunkedBypassAttacks = {
                pattern + "?data=test%0d%0aTransfer-Encoding: chunked%0d%0a%0d%0a1e%0d%0aGET /admin HTTP/1.1%0d%0aHost: bypass%0d%0a0%0d%0a%0d%0a",
                pattern + "?param=chunk%0d%0aTransfer-Encoding: chunked%0d%0a%0d%0a0%0d%0a%0d%0aPOST /admin/users HTTP/1.1%0d%0aContent-Length: 15%0d%0a%0d%0ax=1",
                pattern + "?test=bypass%0d%0aTransfer-Encoding: chunked%0d%0a%0d%0a56%0d%0aGET /sensitive HTTP/1.1%0d%0aHost: internal%0d%0aAuthorization: Bearer token%0d%0a0%0d%0a%0d%0a",
                pattern + "?input=encoding%0d%0aTransfer-Encoding: chunked%0d%0a%0d%0a2a%0d%0aDELETE /admin/users HTTP/1.1%0d%0aHost: vulnerable%0d%0a0%0d%0a%0d%0a",
                pattern + "?payload=chunk%0d%0aTransfer-Encoding: chunked%0d%0a%0d%0a71%0d%0aPOST /admin/elevate HTTP/1.1%0d%0aHost: app%0d%0aContent-Length: 15%0d%0a%0d%0aadmin=true%0d%0a0%0d%0a%0d%0a",
                pattern + "?attack=split%0d%0aTransfer-Encoding: chunked%0d%0a%0d%0a3c%0d%0aGET /admin/config HTTP/1.1%0d%0aHost: target%0d%0aX-Admin: true%0d%0a0%0d%0a%0d%0a",
                pattern + "?method=fragment%0d%0aTransfer-Encoding: chunked%0d%0a%0d%0a4a%0d%0aPUT /admin/settings HTTP/1.1%0d%0aHost: vulnerable%0d%0aContent-Length: 20%0d%0a0%0d%0a%0d%0a"
        };
        return chunkedBypassAttacks[hashBasedSelection(chunkedBypassAttacks.length)];
    }

    private int hashBasedSelection(int max) {
        return Math.abs(this.hashCode()) % max;
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}