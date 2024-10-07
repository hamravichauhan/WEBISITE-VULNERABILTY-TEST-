# Vulnerability Assessment Tool

The Vulnerability Assessment Tool is a Python-based application that allows you to assess the security vulnerabilities of a web application or an Android APK file. It performs various security tests and generates a detailed report of the findings.

## Features

- Checks SSL certificate validity
- Performs OWASP ZAP scan for security issues
- Tests for SQL injection vulnerabilities
- Checks for cross-site scripting (XSS) vulnerabilities
- Verifies HTTP security headers
- Analyzes Android APK files for security risks
- Performs additional security tests such as information disclosure, email header injection, command injection, and more
- Generates a PDF report summarizing the assessment results

## Prerequisites

Before running the Vulnerability Assessment Tool, ensure that you have the following dependencies installed:

- Python 3.x
- OWASP ZAP (running on the specified port)
- `requests` library
- `tkinter` library
- `reportlab` library
- `nmap` library
- `apktool` (for APK analysis)

You can install the required Python libraries using pip:



## Usage

1. Clone the repository or download the source code files.

2. Open a terminal or command prompt and navigate to the directory containing the source code.

3. Run the following command to start the Vulnerability Assessment Tool:

   ```
   python main.py
   ```

4. The Vulnerability Assessment Tool GUI will open.

5. Enter the URL of the web application you want to assess in the "Enter URL" field.

6. If you want to analyze an Android APK file, click the "Browse" button next to "Select APK File" and choose the APK file from your system.

7. Click the "Run Assessment" button to start the vulnerability assessment.

8. The tool will perform various security tests and display the results in the text box below.

9. Once the assessment is complete, a PDF report will be generated automatically. The file path of the generated report will be displayed in the text box.

10. Review the assessment results and the generated PDF report for detailed information about the identified vulnerabilities and their severity.

## Customization

You can customize the Vulnerability Assessment Tool by modifying the source code:

- Add or remove security tests in the `run_assessment` method of the `VulnerabilityAssessmentTool` class.
- Implement additional test functions in the "Vulnerability Assessment Functions" section.
- Modify the PDF report generation in the `generate_report` function to include additional information or change the report format.

## Disclaimer

The Vulnerability Assessment Tool is provided as-is and is intended for educational and testing purposes only. Use it responsibly and only on systems and applications that you have permission to test. The authors and contributors are not responsible for any misuse or damage caused by this tool.

## License

This project is licensed under the [MIT License](LICENSE).
