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
- **Description**: Direct string concatenation of user input into SQL query without parameterization
- **Impact**: Attackers can inject arbitrary SQL commands to bypass authentication, extract sensitive data, modify database contents, or execute administrative operations
- **Recommendation**: Use parameterized queries or prepared statements to separate SQL code from data

**Fix Example**:

```
sql = "SELECT * FROM users WHERE name = ?"
db.execute(sql, (username,))
```

