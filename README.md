**中文** | [English](README_en.md)

# 基于大语言模型的代码安全扫描器

本项目实现了一个安全扫描解决方案，利用 Deepseek 或 GPT-4 或 Claude 等大语言模型 (LLM) 来检测代码库中的漏洞。它可以作为 CLI 工具在本地运行，也可以使用 GitHub Actions 集成到您的 CI/CD 流程中。

**注意：** 本研究的大部分内容是通过使用 LLM 和不同的提示词方法反复试错完成的。

## 整体功能

- 使用 LLM 检测代码中的安全漏洞
- 支持多种编程语言（Python, JavaScript, TypeScript, Java, C/C++, Go, PHP, Ruby）
- 提供详细的漏洞信息，包括：
  - 漏洞类型和描述
  - 严重程度评级
  - 问题发生的行号
  - 漏洞的潜在影响
  - 包含代码示例的修复建议
- 可在本地或 CI/CD 流程中运行
- 为检测到的漏洞创建 GitHub Issues
- 支持 OpenAI、Anthropic 和 DeepSeek 模型
- 可以扫描单个文件或整个目录
- 生成 JSON 或 Markdown 格式的报告

## GitHub Actions 功能

- 在推送、合并请求 (PR) 和每周计划时自动运行
- 在合并请求中仅扫描更改的文件以提高效率
- 在计划运行或推送到 main 分支时执行全量扫描
- 为检测到的漏洞创建 GitHub Issues
- 将扫描结果作为工作流工件上传

## 先决条件

- Python 3.8 或更高版本
- 来自 OpenAI、Anthropic 或 DeepSeek 的 API 密钥
- 用于 CI/CD 集成的 GitHub 仓库

## 安装

1. 克隆此仓库：
   ```bash
   git clone https://github.com/yourusername/llm-code-security-scanner.git
   cd llm-code-security-scanner
   ```

2. 安装所需的包：
   ```bash
   pip install openai anthropic
   ```

3. 设置您的 API 密钥：
   - 对于 OpenAI：
     ```bash
     export OPENAI_API_KEY="your-api-key-here"
     ```
   - 对于 Anthropic：
     ```bash
     export ANTHROPIC_API_KEY="your-api-key-here"
     ```
   - 对于 DeepSeek：
     ```bash
     export DEEPSEEK_API_KEY="your-api-key-here"
     ```

## 本地使用

脚本位于 `scripts` 目录中。扫描器可用于检查单个文件或整个目录：

```bash
# 扫描单个文件
python scripts/llm_security_scanner.py --file vulnerable-code/python/test.py

# 扫描目录
python scripts/llm_security_scanner.py --directory vulnerable-code/python

# 指定输出格式
python scripts/llm_security_scanner.py --directory vulnerable-code/python --output-format markdown --output-file scan-results.md

# 使用 Anthropic 的 Claude 代替 OpenAI
python scripts/llm_security_scanner.py --file vulnerable-code/python/test.py --provider anthropic

# 使用 DeepSeek 模型
python scripts/llm_security_scanner.py --file vulnerable-code/python/test.py --provider deepseek

# 使用 API 密钥参数（如果未设置环境变量）
python scripts/llm_security_scanner.py --file vulnerable-code/python/test.py --api-key your-api-key-here
```

## GitHub Actions 集成

要将安全扫描器集成到您的 GitHub 工作流中，请执行以下操作：

1. 如果仓库中不存在以下目录，请创建它们：
   ```bash
   mkdir -p .github/workflows
   mkdir -p .github/scripts
   ```

2. 将 `llm_security_scanner.py` 文件复制到 `.github/scripts/`：
   ```bash
   cp llm_security_scanner.py .github/scripts/
   ```

3. 将工作流文件复制到 `.github/workflows/`：
   ```bash
   cp llm-security-scan.yml .github/workflows/
   ```

4. 将您的 API 密钥添加为 GitHub Secret：
   - 转到 GitHub 上的仓库
   - 点击 "Settings" > "Secrets and variables" > "Actions"
   - 点击 "New repository secret"
   - 名称：`OPENAI_API_KEY`、`ANTHROPIC_API_KEY` 或 `DEEPSEEK_API_KEY`
   - 值：您的 API 密钥

5. 提交并推送更改：
   ```bash
   git add .github
   git commit -m "Add LLM-based security scanning"
   git push
   ```

工作流现在将在以下情况下运行：
- 每次推送到 `main` 分支时
- 每次向 `main` 分支提交合并请求 (PR) 时
- 每周一 UTC 时间上午 8:00

## 工作原理

安全扫描器使用以下方法：

1. **代码分析**：扫描器从文件中提取代码，并将其发送给 LLM，附带一个精心设计的提示词，指示模型分析代码中的安全漏洞。

2. **漏洞检测**：LLM 处理代码并识别潜在的安全问题，提供有关每个漏洞的详细信息。

3. **报告生成**：扫描器生成 JSON 或 Markdown 格式的报告，详细说明发现结果。

4. **Issue 创建**：在 GitHub Actions 中运行时，扫描器会为中等至严重级别的漏洞创建 GitHub Issues，以便于跟踪和修复。

## 自定义

您可以通过修改以下内容来自定义扫描器的行为：

- `_build_security_prompt` 方法中的安全提示词
- 要检查的漏洞类型
- 创建 Issue 的严重程度阈值
- 要跳过的目录排除列表

## 局限性

- 漏洞检测的准确性取决于所使用的 LLM 的能力
- 大文件可能会超出 LLM 的 Token 限制
- 对于大型代码库，API 成本可能会增加
- 扫描器可能会产生误报或遗漏某些漏洞

## 许可证

[MIT License](LICENSE)

## 致谢

本项目的灵感来自于表明 LLM 可以有效识别代码漏洞并提供有用的修复指导的研究。

- Steve Sims 的研究思路
- Melanie Hart Buehler 关于[使用 LLM 检测不安全代码的研究](https://towardsdatascience.com/detecting-insecure-code-with-llms-8b8ad923dd98/)

## 漏洞代码示例

`vulnerable-code` 目录包含您可以扫描以测试发现结果的示例漏洞代码。目前它是一个存在漏洞的 Python 应用程序，但我会尽快添加更多语言的示例。

## 贡献
源项目地址为https://github.com/iknowjason/llm-security-scanner 本作者仅做部分优化并添加支持deepseek-api.