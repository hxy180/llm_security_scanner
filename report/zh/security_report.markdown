# 安全扫描报告

## 摘要

- 扫描文件总数: 1
- 存在漏洞的文件数: 1
- 发现的漏洞总数: 1

## 漏洞详情

### vulnerable-code/python/test.py

#### SQL Injection

- **严重程度**: Critical
- **行号**: 2
- **描述**: Direct string concatenation of user input into SQL query, allowing attackers to manipulate the query.
- **影响**: Attackers can read, modify, or delete database data, potentially leading to data breach or loss.
- **建议**: Use parameterized queries or prepared statements to separate data from SQL commands.

**修复示例**:

```
cursor.execute('SELECT * FROM users WHERE username = %s AND password = %s', (username, password))
```

