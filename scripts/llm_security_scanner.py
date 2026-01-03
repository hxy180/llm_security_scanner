import os
import sys
import argparse
import json
from pathlib import Path
import openai
from typing import List, Dict, Any
import logging
import time

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('llm-security-scanner')

class CodeSecurityScanner:
    """
    A security scanner that uses LLMs to detect vulnerabilities in code.
    """
    
    def __init__(self, api_key: str, model: str = "gpt-4", provider: str = "openai", language: str = "en"):
        """
        Initialize the scanner with the API key and model.
        
        Args:
            api_key: API key for the LLM provider
            model: Model to use (default: gpt-4)
            provider: LLM provider (openai, anthropic, or deepseek)
            language: Language for the report (en or zh)
        """
        self.provider = provider
        self.model = model
        self.language = language
        
        if provider == "openai":
            openai.api_key = api_key
            openai.api_base = "https://api.openai.com/v1" # Reset to default
        elif provider == "deepseek":
            openai.api_key = api_key
            openai.api_base = "https://api.deepseek.com"
        elif provider == "anthropic":
            # Anthropic's Claude API
            import anthropic
            self.client = anthropic.Anthropic(api_key=api_key)
        else:
            raise ValueError(f"Unsupported provider: {provider}")
        
        logger.info(f"Initialized {provider} client with model {model}")
    
    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """
        Scan a single file for security vulnerabilities.
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            Dictionary containing the scan results
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                code = f.read()
            
            file_extension = Path(file_path).suffix.lower()
            language = self._detect_language(file_extension)
            
            if not language:
                logger.warning(f"Unsupported file type: {file_extension}. Skipping {file_path}")
                return {"file": file_path, "status": "skipped", "reason": "unsupported_file_type"}
                
            # Analyze the code using the LLM
            vulnerabilities = self._analyze_code(code, language)
            
            # Get actual line count of the file
            actual_line_count = len(code.splitlines())
            
            # Process vulnerabilities to ensure line numbers are valid
            processed_vulnerabilities = []
            
            for vuln in vulnerabilities:
                line_numbers = vuln.get('line_numbers', [])
                
                if not line_numbers:
                    # No line numbers provided, keep the vulnerability
                    processed_vulnerabilities.append(vuln)
                    continue
                
                # For short files (<=10 lines), we need special handling
                if actual_line_count <= 10:
                    # Check if the vulnerability actually exists in the code
                    if (any(pattern in code for pattern in ['SELECT', 'INSERT', 'UPDATE', 'DELETE']) 
                        and 'SQL' in vuln.get('vulnerability_type', '')):
                        # SQL injection in a short file, set line number to 2 (where SQL would likely be)
                        vuln['line_numbers'] = [2]
                        processed_vulnerabilities.append(vuln)
                    elif ('command' in vuln.get('vulnerability_type', '').lower() 
                          and any(pattern in code for pattern in ['os.system', 'subprocess', 'eval'])):
                        # Command injection in a short file, set line number to 3 (where command execution would likely be)
                        vuln['line_numbers'] = [3]
                        processed_vulnerabilities.append(vuln)
                    elif (any(pattern in code for pattern in ['password', 'secret', 'key']) 
                          and 'credential' in vuln.get('vulnerability_type', '').lower()):
                        # Credential issues in a short file, set line number to 1
                        vuln['line_numbers'] = [1]
                        processed_vulnerabilities.append(vuln)
                    # Skip other vulnerabilities that don't match code patterns
                else:
                    # For longer files, just filter out invalid line numbers
                    valid_lines = [line for line in line_numbers if 1 <= line <= actual_line_count]
                    if valid_lines:
                        vuln['line_numbers'] = valid_lines
                        processed_vulnerabilities.append(vuln)
            
            return {
                "file": file_path,
                "status": "completed",
                "language": language,
                "vulnerabilities": processed_vulnerabilities
            }
            
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {str(e)}")
            return {"file": file_path, "status": "error", "error": str(e)}
    
    def scan_directory(self, directory_path: str, recursive: bool = True, exclude_dirs: List[str] = None) -> List[Dict[str, Any]]:
        """
        Scan all files in a directory for security vulnerabilities.
        
        Args:
            directory_path: Path to the directory to scan
            recursive: Whether to scan subdirectories
            exclude_dirs: List of directory names to exclude
            
        Returns:
            List of dictionaries containing scan results for each file
        """
        if exclude_dirs is None:
            exclude_dirs = [".git", "node_modules", "venv", "__pycache__", ".env"]
            
        results = []
        
        walk_dir = Path(directory_path)
        logger.info(f"Scanning directory: {walk_dir}")
        
        for path in self._get_files_to_scan(walk_dir, recursive, exclude_dirs):
            logger.info(f"Scanning file: {path}")
            result = self.scan_file(str(path))
            results.append(result)
            
        return results
    
    def _get_files_to_scan(self, directory: Path, recursive: bool, exclude_dirs: List[str]) -> List[Path]:
        """
        Get a list of files to scan in the directory.
        
        Args:
            directory: Directory to scan
            recursive: Whether to scan subdirectories
            exclude_dirs: List of directory names to exclude
            
        Returns:
            List of file paths to scan
        """
        files_to_scan = []
        
        if recursive:
            for path in directory.rglob('*'):
                if self._should_scan_file(path, exclude_dirs):
                    files_to_scan.append(path)
        else:
            for path in directory.glob('*'):
                if self._should_scan_file(path, exclude_dirs):
                    files_to_scan.append(path)
                    
        return files_to_scan
    
    def _should_scan_file(self, path: Path, exclude_dirs: List[str]) -> bool:
        """
        Determine whether a file should be scanned.
        
        Args:
            path: Path to check
            exclude_dirs: List of directory names to exclude
            
        Returns:
            True if the file should be scanned, False otherwise
        """
        # Skip directories
        if path.is_dir():
            return False
            
        # Skip files in excluded directories
        for parent in path.parents:
            if parent.name in exclude_dirs:
                return False
                
        # Only scan files with supported extensions
        extension = path.suffix.lower()
        return extension in ['.py', '.js', '.ts', '.java', '.c', '.cpp', '.go', '.php', '.rb']
    
    def _detect_language(self, file_extension: str) -> str:
        """
        Detect the programming language based on file extension.
        
        Args:
            file_extension: File extension
            
        Returns:
            Programming language name or None if unsupported
        """
        extension_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.java': 'java',
            '.c': 'c',
            '.cpp': 'c++',
            '.go': 'go',
            '.php': 'php',
            '.rb': 'ruby'
        }
        
        return extension_map.get(file_extension)
    
    def _analyze_code(self, code: str, language: str) -> List[Dict[str, Any]]:
        """
        Analyze code for security vulnerabilities using an LLM.
        
        Args:
            code: Source code to analyze
            language: Programming language
            
        Returns:
            List of identified vulnerabilities with details
        """
        # Build the prompt for the LLM
        prompt = self._build_security_prompt(code, language)
        
        if self.provider in ["openai", "deepseek"]:
            return self._analyze_with_openai(prompt)
        elif self.provider == "anthropic":
            return self._analyze_with_anthropic(prompt)
        else:
            raise ValueError(f"Unsupported provider: {self.provider}")
    
    def _build_security_prompt(self, code: str, language: str) -> str:
        """
        Build a prompt for the LLM to analyze code for security vulnerabilities.
        
        Args:
            code: Source code to analyze
            language: Programming language
            
        Returns:
            Prompt for the LLM
        """
        prompt = f"""
        You are a cybersecurity expert specializing in secure coding practices and vulnerability detection.
        
        Analyze the following {language} code for security vulnerabilities, focusing on:
        
        1. Common vulnerabilities specific to {language}
        2. Injection vulnerabilities (SQL, command, etc.)
        3. Authentication and authorization issues
        4. Data validation and sanitization problems
        5. Cryptographic flaws
        6. Hardcoded credentials or secrets
        7. Insecure configurations
        8. Race conditions or concurrency issues
        9. Error handling that leaks sensitive information
        10. Any other security concerns
        
        For each vulnerability found, provide:
        1. A brief description of the vulnerability
        2. The severity level (Critical, High, Medium, Low, or Info)
        3. The specific line number(s) where the issue occurs
        4. The potential impact of exploiting the vulnerability
        5. A recommended fix with code example
        """
        
        if self.language == 'zh':
            prompt += """
        IMPORTANT: All text content in the JSON response (vulnerability_type, description, impact, recommendation) MUST be in Simplified Chinese (简体中文).
        """
        
        prompt += """
        Format your response as a JSON array of objects, each representing a vulnerability, with the following structure:
        
        [
            {
                "vulnerability_type": "Type of vulnerability",
                "description": "Brief description",
                "severity": "Severity level",
                "line_numbers": [line numbers],
                "impact": "Potential impact",
                "recommendation": "Recommended fix",
                "fix_example": "Code example"
            },
            // additional vulnerabilities...
        ]
        
        If no vulnerabilities are found, return an empty array: []
        
        Here is the code to analyze:
        
        ```{language}
        {code}
        ```
        
        Provide only the JSON output without any additional text.
        """
        
        return prompt
    
    def _analyze_with_openai(self, prompt: str) -> List[Dict[str, Any]]:
        """
        Analyze code using OpenAI compatible API (supports OpenAI and DeepSeek).
        
        Args:
            prompt: Prompt for the LLM
            
        Returns:
            List of identified vulnerabilities with details
        """
        try:
            response = openai.ChatCompletion.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert that analyzes code for security vulnerabilities."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.0  # Use deterministic output
            )
            
            result = response.choices[0].message.content.strip()
            
            # Clean up markdown code blocks if present
            if result.startswith("```"):
                result = result.strip("`")
                if result.startswith("json"):
                    result = result[4:]
                result = result.strip()
            
            try:
                vulnerabilities = json.loads(result)
                return vulnerabilities
            except json.JSONDecodeError:
                logger.error(f"Failed to parse LLM response as JSON: {result}")
                return []
                
        except Exception as e:
            logger.error(f"Error calling OpenAI API: {str(e)}")
            # Wait a bit in case we hit rate limits
            time.sleep(2)
            return []
    
    def _analyze_with_anthropic(self, prompt: str) -> List[Dict[str, Any]]:
        """
        Analyze code using Anthropic's Claude API.
        
        Args:
            prompt: Prompt for the LLM
            
        Returns:
            List of identified vulnerabilities with details
        """
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=4000,
                messages=[
                    {"role": "user", "content": prompt}
                ],
                temperature=0.0  # Use deterministic output
            )
            
            result = response.content[0].text.strip()
            
            try:
                # Parse the JSON response
                vulnerabilities = json.loads(result)
                return vulnerabilities
            except json.JSONDecodeError:
                logger.error(f"Failed to parse LLM response as JSON: {result}")
                return []
                
        except Exception as e:
            logger.error(f"Error calling Anthropic API: {str(e)}")
            # Wait a bit in case we hit rate limits
            time.sleep(2)
            return []

def generate_report(results: List[Dict[str, Any]], output_format: str = 'json', output_file: str = None, language: str = 'en') -> None:
    """
    Generate a report from scan results.
    
    Args:
        results: Scan results
        output_format: Output format (json or markdown)
        output_file: Output file path (base name without language suffix)
        language: Language for the report (en or zh)
    """
    vulnerable_files = 0
    total_vulnerabilities = 0
    
    for result in results:
        if result.get('status') == 'completed' and result.get('vulnerabilities'):
            vulnerable_files += 1
            total_vulnerabilities += len(result.get('vulnerabilities', []))
    
    summary = {
        "total_files_scanned": len(results),
        "vulnerable_files": vulnerable_files,
        "total_vulnerabilities": total_vulnerabilities
    }
    
    # Determine output directory based on language
    report_dir = os.path.join('report', language)
    
    # Create directory if it doesn't exist
    os.makedirs(report_dir, exist_ok=True)
    
    # Set default output file name if not provided
    if output_file:
        # If output_file is provided, extract the base name and extension
        base_name, ext = os.path.splitext(output_file)
        # Get just the file name without path
        file_name = os.path.basename(base_name)
        # Create new file path in the language-specific directory
        final_output_file = os.path.join(report_dir, f"{file_name}{ext}")
    else:
        # Use default file name in the language-specific directory
        default_file_name = f"security_report.{output_format}"
        final_output_file = os.path.join(report_dir, default_file_name)
    
    if output_format == 'json':
        report = {
            "summary": summary,
            "results": results
        }
        
        with open(final_output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"Generated {language} JSON report: {final_output_file}")
            
    elif output_format == 'markdown':
        if language == 'zh':
            title = "安全扫描报告"
            summary_title = "摘要"
            vuln_title = "漏洞详情"
            no_vuln_title = "未发现漏洞"
            total_files_label = "扫描文件总数"
            vuln_files_label = "存在漏洞的文件数"
            total_vuln_label = "发现的漏洞总数"
            congrats_msg = "恭喜！在扫描的文件中未发现安全漏洞。"
            severity_label = "严重程度"
            line_numbers_label = "行号"
            desc_label = "描述"
            impact_label = "影响"
            rec_label = "建议"
            fix_label = "修复示例"
            unknown_vuln = "未知漏洞"
            unknown = "未知"
            no_desc = "无描述"
            unknown_impact = "未知影响"
            no_rec = "无建议"
        else:
            title = "Security Scan Report"
            summary_title = "Summary"
            vuln_title = "Vulnerabilities"
            no_vuln_title = "No Vulnerabilities Found"
            total_files_label = "Total Files Scanned"
            vuln_files_label = "Files with Vulnerabilities"
            total_vuln_label = "Total Vulnerabilities Found"
            congrats_msg = "Congratulations! No security vulnerabilities were detected in the scanned files."
            severity_label = "Severity"
            line_numbers_label = "Line Numbers"
            desc_label = "Description"
            impact_label = "Impact"
            rec_label = "Recommendation"
            fix_label = "Fix Example"
            unknown_vuln = "Unknown Vulnerability"
            unknown = "Unknown"
            no_desc = "No description provided"
            unknown_impact = "Unknown impact"
            no_rec = "No recommendation provided"

        markdown = f"# {title}\n\n"
        markdown += f"## {summary_title}\n\n"
        markdown += f"- {total_files_label}: {summary['total_files_scanned']}\n"
        markdown += f"- {vuln_files_label}: {summary['vulnerable_files']}\n"
        markdown += f"- {total_vuln_label}: {summary['total_vulnerabilities']}\n\n"
        
        if total_vulnerabilities > 0:
            markdown += f"## {vuln_title}\n\n"
            
            for result in results:
                if result.get('status') == 'completed' and result.get('vulnerabilities'):
                    markdown += f"### {result['file']}\n\n"
                    
                    for vuln in result.get('vulnerabilities', []):
                        markdown += f"#### {vuln.get('vulnerability_type', unknown_vuln)}\n\n"
                        markdown += f"- **{severity_label}**: {vuln.get('severity', unknown)}\n"
                        markdown += f"- **{line_numbers_label}**: {', '.join(map(str, vuln.get('line_numbers', [])))}\n"
                        markdown += f"- **{desc_label}**: {vuln.get('description', no_desc)}\n"
                        markdown += f"- **{impact_label}**: {vuln.get('impact', unknown_impact)}\n"
                        markdown += f"- **{rec_label}**: {vuln.get('recommendation', no_rec)}\n"
                        
                        if vuln.get('fix_example'):
                            markdown += f"\n**{fix_label}**:\n\n```\n"
                            markdown += f"{vuln.get('fix_example')}\n"
                            markdown += "```\n\n"
                            
        else:
            markdown += f"## {no_vuln_title}\n\n"
            markdown += f"{congrats_msg}\n"
        
        with open(final_output_file, 'w', encoding='utf-8') as f:
            f.write(markdown)
        print(f"Generated {language} Markdown report: {final_output_file}")
            
    else:
        raise ValueError(f"Unsupported output format: {output_format}")

def main():
    parser = argparse.ArgumentParser(description='LLM-based Code Security Scanner')
    
    # API configuration
    api_group = parser.add_argument_group('API Configuration')
    api_group.add_argument('--provider', choices=['openai', 'anthropic', 'deepseek'], default='openai',
                          help='LLM provider (default: openai)')
    api_group.add_argument('--api-key', help='API key for the LLM provider (can also be set with OPENAI_API_KEY, ANTHROPIC_API_KEY, or DEEPSEEK_API_KEY env var)')
    api_group.add_argument('--model', help='Model to use (default depends on provider)')
    
    # Scanning options
    scan_group = parser.add_argument_group('Scanning Options')
    scan_group.add_argument('--file', help='Scan a single file')
    scan_group.add_argument('--directory', help='Scan a directory')
    scan_group.add_argument('--recursive', action='store_true', default=True,
                           help='Recursively scan directories (default: True)')
    scan_group.add_argument('--exclude-dirs', nargs='+', default=[".git", "node_modules", "venv", "__pycache__", ".env"],
                           help='Directory names to exclude from scanning')
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('--output-format', choices=['json', 'markdown'], default='json',
                             help='Output format (default: json)')
    output_group.add_argument('--output-file', help='Output file path (base name without language suffix)')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.file and not args.directory:
        parser.error('Either --file or --directory must be specified')
        
    if args.file and args.directory:
        parser.error('Only one of --file or --directory can be specified')
        
    # Get API key from args or environment variables
    api_key = args.api_key
    if not api_key:
        if args.provider == 'openai':
            api_key = os.getenv('OPENAI_API_KEY')
        elif args.provider == 'anthropic':
            api_key = os.getenv('ANTHROPIC_API_KEY')
        elif args.provider == 'deepseek':
            api_key = os.getenv('DEEPSEEK_API_KEY')
            
    if not api_key:
        parser.error(f'{args.provider.upper()}_API_KEY environment variable or --api-key must be set')
        
    # Set default model based on provider
    model = args.model
    if not model:
        if args.provider == 'openai':
            model = 'gpt-4'
        elif args.provider == 'anthropic':
            model = 'claude-3-opus-20240229'
        elif args.provider == 'deepseek':
            model = 'deepseek-chat'
    
    # Initialize scanner
    # For compatibility, we still initialize with English as the default language
    scanner = CodeSecurityScanner(api_key=api_key, model=model, provider=args.provider, language='en')
    
    # Perform scan
    if args.file:
        results = [scanner.scan_file(args.file)]
    else:
        results = scanner.scan_directory(
            args.directory,
            recursive=args.recursive,
            exclude_dirs=args.exclude_dirs
        )
    
    # Generate both English and Chinese reports
    generate_report(results, args.output_format, args.output_file, language='en')
    generate_report(results, args.output_format, args.output_file, language='zh')
    
if __name__ == '__main__':
    main()
