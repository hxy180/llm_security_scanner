# 安全扫描报告

## 摘要

- 扫描文件总数: 1
- 存在漏洞的文件数: 1
- 发现的漏洞总数: 7

## 漏洞详情

### vulnerable-code/python/app.py

#### SQL Injection

- **严重程度**: Critical
- **行号**: 15
- **描述**: Direct string concatenation of user input into SQL query, allowing attackers to manipulate the query.
- **影响**: Attackers can read, modify, or delete database data, potentially leading to data breach or loss.
- **建议**: Use parameterized queries or prepared statements to separate data from SQL commands.

**修复示例**:

```
cursor.execute('SELECT * FROM users WHERE username = %s AND password = %s', (username, password))
```

#### Command Injection

- **严重程度**: Critical
- **行号**: 22
- **描述**: User input is directly passed to os.system() without validation or sanitization.
- **影响**: Attackers can execute arbitrary commands on the server, leading to full system compromise.
- **建议**: Avoid os.system(); use subprocess with shell=False and validate/sanitize input. Use allowlists for commands.

**修复示例**:

```
import subprocess; subprocess.run(['ls', user_input], shell=False) if user_input in allowed_commands else None
```

#### Hardcoded Credentials

- **严重程度**: High
- **行号**: 5, 6
- **描述**: Database credentials are hardcoded in the source code.
- **影响**: If source code is exposed, attackers gain direct access to the database.
- **建议**: Store credentials in environment variables or a secure configuration file (e.g., .env) not tracked in version control.

**修复示例**:

```
import os; DB_USER = os.getenv('DB_USER'); DB_PASS = os.getenv('DB_PASS')
```

#### Weak Cryptographic Hash

- **严重程度**: High
- **行号**: 13
- **描述**: Using MD5 for password hashing, which is cryptographically broken and fast to compute, making it vulnerable to brute-force attacks.
- **影响**: Passwords can be easily cracked, leading to account compromise.
- **建议**: Use a strong, slow hashing algorithm like bcrypt, scrypt, or Argon2 with a salt.

**修复示例**:

```
import bcrypt; hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
```

#### Insecure Error Handling

- **严重程度**: Medium
- **行号**: 18, 23
- **描述**: Raw exception details are printed to the user, potentially leaking sensitive information like stack traces or system details.
- **影响**: Attackers can gain insights into the application's internal structure, aiding further attacks.
- **建议**: Log exceptions securely on the server and return generic error messages to the user.

**修复示例**:

```
import logging; logging.exception('Database error'); return 'An internal error occurred.'
```

#### Missing Input Validation

- **严重程度**: Medium
- **行号**: 11, 12, 21
- **描述**: User inputs (username, password, command) are not validated for length, type, or malicious content before use.
- **影响**: Can lead to injection attacks, buffer overflows (in other contexts), or resource exhaustion.
- **建议**: Validate all user inputs against strict criteria (e.g., length, allowed characters) using a library like Pydantic or built-in checks.

**修复示例**:

```
if not username.isalnum() or len(username) > 20: raise ValueError('Invalid username')
```

#### Insecure Default Configuration

- **严重程度**: Medium
- **行号**: 7
- **描述**: The database connection may use an insecure protocol or lack SSL/TLS if not explicitly configured.
- **影响**: Database traffic could be intercepted, leading to data exposure.
- **建议**: Enforce SSL/TLS for the database connection and use secure configurations.

**修复示例**:

```
conn = mysql.connector.connect(..., ssl_ca='/path/to/ca.pem', ssl_verify_cert=True)
```

