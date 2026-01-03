# 快速开始 - 运行代码示例

## 方式一：使用环境变量（推荐）

### Windows PowerShell

```powershell
# 1. 设置 DeepSeek API 密钥（推荐，性价比高）
$env:DEEPSEEK_API_KEY="your-deepseek-api-key-here"

# 2. 扫描单个文件（中文输出）
python scripts/llm_security_scanner.py --file vulnerable-code/python/test.py --provider deepseek --language zh

# 3. 扫描整个目录并生成报告
python scripts/llm_security_scanner.py --directory vulnerable-code/python --provider deepseek --output-format markdown --output-file scan-results.md --language zh
```

### Windows CMD

```cmd
set DEEPSEEK_API_KEY=your-deepseek-api-key-here
python scripts/llm_security_scanner.py --file vulnerable-code/python/test.py --provider deepseek --language zh
```

## 方式二：使用命令行参数

```powershell
# 直接使用 API 密钥参数
python scripts/llm_security_scanner.py --file vulnerable-code/python/test.py --provider deepseek --api-key "your-api-key-here" --language zh
```

## 完整示例命令

### 示例 1：扫描单个文件（中文输出）

```powershell
$env:DEEPSEEK_API_KEY="your-api-key"
python scripts/llm_security_scanner.py --file vulnerable-code/python/test.py --provider deepseek --language zh
```

### 示例 2：扫描目录并保存为 Markdown

```powershell
$env:DEEPSEEK_API_KEY="your-api-key"
python scripts/llm_security_scanner.py --directory vulnerable-code/python --provider deepseek --output-format markdown --output-file scan-results.md --language zh
```

### 示例 3：扫描目录并保存为 JSON

```powershell
$env:DEEPSEEK_API_KEY="your-api-key"
python scripts/llm_security_scanner.py --directory vulnerable-code/python --provider deepseek --output-format json --output-file scan-results.json --language zh
```

### 示例 4：使用 OpenAI

```powershell
$env:OPENAI_API_KEY="your-openai-api-key"
python scripts/llm_security_scanner.py --file vulnerable-code/python/test.py --provider openai --language zh
```

### 示例 5：使用 Anthropic Claude

```powershell
$env:ANTHROPIC_API_KEY="your-anthropic-api-key"
python scripts/llm_security_scanner.py --file vulnerable-code/python/test.py --provider anthropic --language zh
```

## 参数说明

- `--file`: 扫描单个文件
- `--directory`: 扫描整个目录
- `--provider`: 选择 LLM 提供商（openai, anthropic, deepseek）
- `--api-key`: API 密钥（如果未设置环境变量）
- `--language`: 输出语言（en 或 zh）
- `--output-format`: 输出格式（json 或 markdown）
- `--output-file`: 输出文件路径

## 注意事项

1. **API 密钥**：请将 `your-api-key-here` 替换为您的实际 API 密钥
2. **DeepSeek 推荐**：DeepSeek 性价比高，适合测试使用
3. **中文输出**：使用 `--language zh` 可以输出中文报告
4. **文件路径**：确保从项目根目录运行命令

