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
 * T14: LDAP Injection Attack Generator
 * 
 * <p>
 * This generator creates comprehensive LDAP injection attack patterns that attempt
 * to manipulate LDAP queries and directory searches through web application inputs.
 * LDAP injection is a serious vulnerability that can lead to unauthorized directory
 * access, authentication bypass, and information disclosure in applications using
 * LDAP directories for authentication or data storage.
 * </p>
 * 
 * <h3>Attack Types Generated</h3>
 * <ul>
 *   <li>AND/OR Logic Manipulation - Boolean logic injection in LDAP filters</li>
 *   <li>Authentication Bypass - Login credential manipulation attacks</li>
 *   <li>Wildcard Injection - LDAP wildcard character exploitation</li>
 *   <li>Comment-based Attacks - LDAP comment injection techniques</li>
 *   <li>Filter Escape Attacks - LDAP filter character escaping bypass</li>
 *   <li>Attribute Enumeration - Directory attribute discovery attacks</li>
 *   <li>DN Manipulation - Distinguished Name injection attacks</li>
 *   <li>Blind LDAP Injection - Information extraction via response timing</li>
 *   <li>Error-based LDAP Attacks - Directory error information disclosure</li>
 *   <li>Base DN Traversal - Directory tree traversal attacks</li>
 *   <li>Schema Discovery - LDAP schema information extraction</li>
 *   <li>User Enumeration - Directory user account discovery</li>
 *   <li>Group Membership Attacks - Group-based access control bypass</li>
 *   <li>Nested Filter Injection - Complex nested LDAP filter attacks</li>
 *   <li>Unicode LDAP Attacks - Unicode-based LDAP filter bypass</li>
 * </ul>
 * 
 * <h3>Security Standards Compliance</h3>
 * <ul>
 *   <li>OWASP Top 10: A03:2021 – Injection</li>
 *   <li>CWE-90: Improper Neutralization of Special Elements used in an LDAP Query</li>
 *   <li>CWE-74: Improper Neutralization of Special Elements in Output</li>
 *   <li>NIST SP 800-63B: Authentication and Lifecycle Management</li>
 *   <li>ISO 27001: A.9.2.1 User registration and de-registration</li>
 * </ul>
 * 
 * @see de.cuioss.tools.security.http.tests.LdapInjectionAttackTest
 * @author Generated for HTTP Security Validation (T14)
 * @version 1.0.0
 */
public class LdapInjectionAttackGenerator implements TypedGenerator<String> {

    private static final String[] BASE_URLS = {
            "http://example.com/auth/login",
            "https://app.domain.com/directory/search",
            "http://localhost:8080/ldap/query",
            "https://secure.site.org/user/lookup",
            "http://test.example.com/admin/users"
    };

    private static final String[] LDAP_OPERATORS = {
            ")", "(", "&", "|", "!", "=", "~=", ">=", "<=", "*"
    };

    private static final String[] ATTRIBUTE_NAMES = {
            "uid", "cn", "sn", "givenName", "mail", "userPassword",
            "memberOf", "objectClass", "distinguishedName", "samAccountName"
    };

    private static final String[] COMMON_VALUES = {
            "admin", "user", "test", "guest", "root", "administrator",
            "service", "system", "ldap", "directory"
    };

    @Override
    public String next() {
        String baseUrl = BASE_URLS[hashBasedSelection(BASE_URLS.length)];

        return switch (hashBasedSelection(15)) {
            case 0 -> createAndOrLogicManipulation(baseUrl);
            case 1 -> createAuthenticationBypass(baseUrl);
            case 2 -> createWildcardInjection(baseUrl);
            case 3 -> createCommentBasedAttack(baseUrl);
            case 4 -> createFilterEscapeAttack(baseUrl);
            case 5 -> createAttributeEnumeration(baseUrl);
            case 6 -> createDnManipulation(baseUrl);
            case 7 -> createBlindLdapInjection(baseUrl);
            case 8 -> createErrorBasedLdapAttack(baseUrl);
            case 9 -> createBaseDnTraversal(baseUrl);
            case 10 -> createSchemaDiscovery(baseUrl);
            case 11 -> createUserEnumeration(baseUrl);
            case 12 -> createGroupMembershipAttack(baseUrl);
            case 13 -> createNestedFilterInjection(baseUrl);
            case 14 -> createUnicodeLdapAttack(baseUrl);
            default -> createAndOrLogicManipulation(baseUrl);
        };
    }

    private String createAndOrLogicManipulation(String pattern) {
        String[] logicAttacks = {
                "admin)(&(objectClass=*",
                "*)|(uid=admin",
                "test)(&(1=1",
                "user)|(objectClass=person)(&(uid=*",
                "admin))%00",
                "*)|(cn=*",
                "test)(&(|(uid=admin)(uid=root))"
        };
        String attack = logicAttacks[hashBasedSelection(logicAttacks.length)];
        return pattern + "?username=" + attack;
    }

    private String createAuthenticationBypass(String pattern) {
        String[] bypassAttacks = {
                "*)(uid=*))(|(uid=*",
                "admin)(&(password=*))",
                "*)|(objectClass=*",
                "*))%00(&(objectClass=user",
                "admin))(|(cn=*",
                "user*)(|(uid=*",
                "*)(userPassword=*)"
        };
        String attack = bypassAttacks[hashBasedSelection(bypassAttacks.length)];
        return pattern + "?user=" + attack + "&password=anything";
    }

    private String createWildcardInjection(String pattern) {
        String[] wildcardAttacks = {
                "a*",
                "*admin*",
                "user*",
                "*",
                "t*st",
                "*@domain.com",
                "admin*)(objectClass=*",
                "*)(|(uid=*"
        };
        String attack = wildcardAttacks[hashBasedSelection(wildcardAttacks.length)];
        return pattern + "?search=" + attack;
    }

    private String createCommentBasedAttack(String pattern) {
        String[] commentAttacks = {
                "admin#",
                "user'--",
                "test/*comment*/",
                "admin){*comment*}",
                "user)#(objectClass=*",
                "admin)//comment",
                "test){//bypass}"
        };
        String attack = commentAttacks[hashBasedSelection(commentAttacks.length)];
        return pattern + "?name=" + attack;
    }

    private String createFilterEscapeAttack(String pattern) {
        String[] escapeAttacks = {
                "admin\\29\\28uid=*",
                "user\\2A\\29\\28objectClass=*",
                "test\\5C\\29\\28cn=*",
                "admin\\00)(uid=*",
                "user\\3D\\29\\28mail=*",
                "test\\28\\29\\7C\\28uid=*",
                "admin\\21\\29\\28objectClass=*"
        };
        String attack = escapeAttacks[hashBasedSelection(escapeAttacks.length)];
        return pattern + "?filter=" + attack;
    }

    private String createAttributeEnumeration(String pattern) {
        String[] enumAttacks = {
                "admin)(mail=*",
                "user)(userPassword=*",
                "test)(memberOf=*",
                "admin)(telephoneNumber=*",
                "user)(homeDirectory=*",
                "test)(loginShell=*",
                "admin)(gecos=*"
        };
        String attack = enumAttacks[hashBasedSelection(enumAttacks.length)];
        return pattern + "?attr=" + attack;
    }

    private String createDnManipulation(String pattern) {
        String[] dnAttacks = {
                "cn=admin,dc=domain,dc=com)(&(objectClass=*",
                "uid=user,ou=people,dc=test)|(cn=*",
                "cn=test)(&(ou=*",
                "uid=admin,cn=users,dc=domain)|(uid=*",
                "cn=service,ou=system)(&(objectClass=*",
                "uid=guest,ou=people)|(objectClass=*",
                "cn=root,dc=admin)(&(cn=*"
        };
        String attack = dnAttacks[hashBasedSelection(dnAttacks.length)];
        return pattern + "?dn=" + attack;
    }

    private String createBlindLdapInjection(String pattern) {
        String[] blindAttacks = {
                "admin)(&(objectClass=person)(cn=a*",
                "user)(&(objectClass=*)(uid=u*",
                "test)(&(mail=*@domain.com)(cn=t*",
                "admin)(&(userPassword=*)(uid=a*",
                "user)(&(memberOf=*)(cn=u*",
                "test)(&(telephoneNumber=*)(uid=t*",
                "admin)(&(homeDirectory=*)(cn=a*"
        };
        String attack = blindAttacks[hashBasedSelection(blindAttacks.length)];
        return pattern + "?query=" + attack;
    }

    private String createErrorBasedLdapAttack(String pattern) {
        String[] errorAttacks = {
                "admin)(&(invalidattr=*",
                "user)(&(nonexistent=test",
                "test)(&(badfilter=*",
                "admin)(&(malformed=",
                "user)(&(invalid)",
                "test)(&(broken=*)()",
                "admin)(&(error=*)(invalid"
        };
        String attack = errorAttacks[hashBasedSelection(errorAttacks.length)];
        return pattern + "?param=" + attack;
    }

    private String createBaseDnTraversal(String pattern) {
        String[] traversalAttacks = {
                "../cn=admin,dc=domain,dc=com",
                "../../ou=people,dc=test,dc=com",
                "../../../dc=com",
                "..\\cn=root,dc=admin",
                "../ou=system,dc=directory",
                "../../cn=config,dc=ldap",
                "../../../cn=schema,cn=config"
        };
        String attack = traversalAttacks[hashBasedSelection(traversalAttacks.length)];
        return pattern + "?base=" + attack;
    }

    private String createSchemaDiscovery(String pattern) {
        String[] schemaAttacks = {
                "admin)(&(objectClass=subschema",
                "user)(&(attributeTypes=*",
                "test)(&(objectClasses=*",
                "admin)(&(ldapSyntaxes=*",
                "user)(&(matchingRules=*",
                "test)(&(namingContexts=*",
                "admin)(&(supportedLDAPVersion=*"
        };
        String attack = schemaAttacks[hashBasedSelection(schemaAttacks.length)];
        return pattern + "?schema=" + attack;
    }

    private String createUserEnumeration(String pattern) {
        String[] userEnumAttacks = {
                "a*)(&(objectClass=person)(uid=a*",
                "admin*)(&(cn=admin*",
                "user*)(&(sn=user*",
                "test*)(&(givenName=test*",
                "service*)(&(objectClass=*",
                "guest*)(&(uid=guest*",
                "root*)(&(cn=root*"
        };
        String attack = userEnumAttacks[hashBasedSelection(userEnumAttacks.length)];
        return pattern + "?users=" + attack;
    }

    private String createGroupMembershipAttack(String pattern) {
        String[] groupAttacks = {
                "admin)(&(memberOf=cn=admins,*",
                "user)(&(memberOf=cn=users,ou=groups,*",
                "test)(&(memberOf=*,dc=domain,dc=com",
                "admin)(&(member=uid=admin,*",
                "user)(&(uniqueMember=cn=user,*",
                "test)(&(memberUid=test*",
                "admin)(&(groupOfNames=*"
        };
        String attack = groupAttacks[hashBasedSelection(groupAttacks.length)];
        return pattern + "?group=" + attack;
    }

    private String createNestedFilterInjection(String pattern) {
        String[] nestedAttacks = {
                "admin)(&(objectClass=*)(&(uid=*",
                "user)(&(cn=*)(&(mail=*",
                "test)(&(sn=*)(&(givenName=*",
                "admin)(|(objectClass=*)(&(uid=*",
                "user)(|(cn=*)(&(mail=*",
                "test)(&(objectClass=*)(|(uid=*",
                "admin)(&(|(cn=*)(sn=*))"
        };
        String attack = nestedAttacks[hashBasedSelection(nestedAttacks.length)];
        return pattern + "?nested=" + attack;
    }

    private String createUnicodeLdapAttack(String pattern) {
        String[] unicodeAttacks = {
                "admin\u0029\u0028uid=*",
                "user\u007C\u0028objectClass=*",
                "test\u0026\u0028cn=*",
                "admin\u002A\u0029\u0028mail=*",
                "user\u0021\u0029\u0028sn=*",
                "test\u003D\u0029\u0028uid=*",
                "admin\u007E\u003D\u0029\u0028objectClass=*"
        };
        String attack = unicodeAttacks[hashBasedSelection(unicodeAttacks.length)];
        return pattern + "?unicode=" + attack;
    }

    private int hashBasedSelection(int max) {
        return Math.abs(this.hashCode()) % max;
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}