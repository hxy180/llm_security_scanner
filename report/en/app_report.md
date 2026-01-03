# Security Scan Report

## Summary

- Total Files Scanned: 1
- Files with Vulnerabilities: 1
- Total Vulnerabilities Found: 7

## Vulnerabilities

### vulnerable-code/python/app.py

#### SQL Injection

- **Severity**: Critical
- **Line Numbers**: 15
- **Description**: Direct string concatenation of user input into SQL query, allowing attackers to manipulate the query.
- **Impact**: Attackers can read, modify, or delete database data, potentially leading to data breach or loss.
- **Recommendation**: Use parameterized queries or prepared statements to separate data from SQL commands.

**Fix Example**:

```
cursor.execute('SELECT * FROM users WHERE username = %s AND password = %s', (username, password))
```

#### Command Injection

- **Severity**: Critical
- **Line Numbers**: 22
- **Description**: User input is directly passed to os.system() without validation or sanitization.
- **Impact**: Attackers can execute arbitrary commands on the server, leading to full system compromise.
- **Recommendation**: Avoid os.system(); use subprocess with shell=False and validate/sanitize input. Use allowlists for commands.

**Fix Example**:

```
import subprocess; subprocess.run(['ls', user_input], shell=False) if user_input in allowed_commands else None
```

#### Hardcoded Credentials

- **Severity**: High
- **Line Numbers**: 5, 6
- **Description**: Database credentials are hardcoded in the source code.
- **Impact**: If source code is exposed, attackers gain direct access to the database.
- **Recommendation**: Store credentials in environment variables or a secure configuration file (e.g., .env) not tracked in version control.

**Fix Example**:

```
import os; DB_USER = os.getenv('DB_USER'); DB_PASS = os.getenv('DB_PASS')
```

#### Weak Cryptographic Hash

- **Severity**: High
- **Line Numbers**: 13
- **Description**: Using MD5 for password hashing, which is cryptographically broken and fast to compute, making it vulnerable to brute-force attacks.
- **Impact**: Passwords can be easily cracked, leading to account compromise.
- **Recommendation**: Use a strong, slow hashing algorithm like bcrypt, scrypt, or Argon2 with a salt.

**Fix Example**:

```
import bcrypt; hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
```

#### Insecure Error Handling

- **Severity**: Medium
- **Line Numbers**: 18, 23
- **Description**: Raw exception details are printed to the user, potentially leaking sensitive information like stack traces or system details.
- **Impact**: Attackers can gain insights into the application's internal structure, aiding further attacks.
- **Recommendation**: Log exceptions securely on the server and return generic error messages to the user.

**Fix Example**:

```
import logging; logging.exception('Database error'); return 'An internal error occurred.'
```

#### Missing Input Validation

- **Severity**: Medium
- **Line Numbers**: 11, 12, 21
- **Description**: User inputs (username, password, command) are not validated for length, type, or malicious content before use.
- **Impact**: Can lead to injection attacks, buffer overflows (in other contexts), or resource exhaustion.
- **Recommendation**: Validate all user inputs against strict criteria (e.g., length, allowed characters) using a library like Pydantic or built-in checks.

**Fix Example**:

```
if not username.isalnum() or len(username) > 20: raise ValueError('Invalid username')
```

#### Insecure Default Configuration

- **Severity**: Medium
- **Line Numbers**: 7
- **Description**: The database connection may use an insecure protocol or lack SSL/TLS if not explicitly configured.
- **Impact**: Database traffic could be intercepted, leading to data exposure.
- **Recommendation**: Enforce SSL/TLS for the database connection and use secure configurations.

**Fix Example**:

```
conn = mysql.connector.connect(..., ssl_ca='/path/to/ca.pem', ssl_verify_cert=True)
```

