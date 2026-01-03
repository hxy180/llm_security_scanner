# Security Scan Report

## Summary

- Total Files Scanned: 1
- Files with Vulnerabilities: 1
- Total Vulnerabilities Found: 1

## Vulnerabilities

### vulnerable-code/python/test.py

#### SQL Injection

- **Severity**: Critical
- **Line Numbers**: 2
- **Description**: Direct string concatenation of user input into SQL query, allowing attackers to manipulate the query.
- **Impact**: Attackers can read, modify, or delete database data, potentially leading to data breach or loss.
- **Recommendation**: Use parameterized queries or prepared statements to separate data from SQL commands.

**Fix Example**:

```
cursor.execute('SELECT * FROM users WHERE username = %s AND password = %s', (username, password))
```

