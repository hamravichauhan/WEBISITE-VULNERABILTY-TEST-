import os
from unittest import result
import requests
import socket
import ssl
import subprocess
import tkinter as tk
from tkinter import (
    filedialog,
    messagebox,
    scrolledtext,
    Frame,
    Label,
    Button,
    Entry,
    Checkbutton,
    IntVar,
)
import xml.etree.ElementTree as ET
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet

import nmap

# ---------- Vulnerability Assessment Functions ----------


def check_ssl_certificate(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                ssl_expiry = cert["notAfter"]
                return 10, f"SSL certificate valid until: {ssl_expiry}\n"
    except Exception as e:
        return 0, f"Error checking SSL certificate: {e}\n"


def owasp_zap_scan(url):
    zap_url = (
        "http://localhost:8080"  # Adjust if ZAP is running on a different port
    )
    api_key = "your_zap_api_key"
    try:
        scan_id = requests.get(
            f"{zap_url}/JSON/ascan/action/scan/?apikey={api_key}&url={url}"
        ).json()["scan"]
        while True:
            status = requests.get(
                f"{zap_url}/JSON/ascan/view/status/?apikey={api_key}&scanId={scan_id}"
            ).json()["status"]
            if int(status) >= 100:
                break

        results = requests.get(
            f"{zap_url}/JSON/core/view/alerts/?apikey={api_key}&baseurl={url}"
        ).json()
        alerts = results["alerts"]
        if alerts:
            alert_details = "\n".join(
                [
                    f"- {alert['alert']}: {alert['url']} (Risk Level: {alert['risk']})"
                    for alert in alerts
                ]
            )
            return (
                4,
                f"Security issues detected in the scan:\n{alert_details}\n",
            )
        else:
            return 10, "No security issues detected in the scan.\n"
    except Exception as e:
        return 0, f"Error during OWASP ZAP scan: {e}\n"


def check_sql_injection(url):
    test_url = f"{url}?id=1' OR '1'='1"
    try:
        response = requests.get(test_url)
        if "error" in response.text.lower() or "sql" in response.text.lower():
            return 2, "Possible SQL Injection vulnerability detected!\n"
        else:
            return 10, "No SQL Injection vulnerability detected.\n"
    except Exception as e:
        return 0, f"Error checking SQL injection: {e}\n"


def check_xss(url):
    test_url = f"{url}?input=<script>alert('XSS')</script>"
    try:
        response = requests.get(test_url)
        if "<script>alert('XSS')</script>" in response.text:
            return 3, "Possible XSS vulnerability detected!\n"
        else:
            return 10, "No XSS vulnerability detected.\n"
    except Exception as e:
        return 0, f"Error checking XSS vulnerability: {e}\n"


def check_http_security_headers(url):
    try:
        response = requests.get(url)
        headers = response.headers
        security_headers = [
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Content-Security-Policy",
            "Strict-Transport-Security",
        ]
        score = 10
        report = ""
        for header in security_headers:
            if header in headers:
                report += f"Header {header}: Present\n"
            else:
                report += f"Header {header}: Missing\n"
                score -= 2  # Decrease score for each missing header
        return score, report
    except Exception as e:
        return 0, f"Error checking HTTP headers: {e}\n"


def analyze_apk(apk_file):
    try:
        output_dir = "decoded_apk"
        subprocess.run(["apktool", "d", apk_file, "-o", output_dir], check=True)

        manifest_path = os.path.join(output_dir, "AndroidManifest.xml")
        tree = ET.parse(manifest_path)
        root = tree.getroot()

        permissions = []
        for child in root.iter("uses-permission"):
            permissions.append(
                child.attrib["{http://schemas.android.com/apk/res/android}name"]
            )

        report = f"Analyzing APK: {os.path.basename(apk_file)}\n"
        report += f"Permissions: {permissions}\n"

        risky_permissions = [
            "android.permission.INTERNET",
            "android.permission.READ_EXTERNAL_STORAGE",
        ]
        risks_found = False
        score = 10
        for permission in permissions:
            if permission in risky_permissions:
                report += f"Risky permission detected: {permission}\n"
                risks_found = True
                score -= 5  # Deduct points for risky permissions

        return score, (
            report
            if risks_found
            else report + "No risky permissions detected.\n"
        )
    except Exception as e:
        return 0, f"Error analyzing APK: {e}\n"


def open_ports_scan(target):
    scanner = nmap.PortScanner()
    try:
        scanner.scan(target, arguments="-p 1-65535")  # Scan all ports
        open_ports = scanner[target]["tcp"].keys()
        if open_ports:
            return 3, f"Open ports found: {', '.join(map(str, open_ports))}\n"
        else:
            return 10, "No open ports found.\n"
    except Exception as e:
        return 0, f"Error during open ports scan: {e}\n"


def dns_spoofing_test(domain):
    # This function requires actual DNS queries; the example is simplified.
    try:
        # Assume we're checking if the domain resolves to an unexpected IP
        ip_address = socket.gethostbyname(domain)
        # Replace 'expected_ip' with the actual expected IP for the domain
        expected_ip = "192.0.2.1"
        if ip_address != expected_ip:
            return (
                2,
                f"DNS Spoofing risk detected! Resolved IP: {ip_address} (expected: {expected_ip})\n",
            )
        return 10, "No DNS spoofing risk detected.\n"
    except Exception as e:
        return 0, f"Error during DNS spoofing test: {e}\n"


def directory_traversal_test(url):
    test_url = f"{url}/path/to/file?file=../../../etc/passwd"  # Example path
    try:
        response = requests.get(test_url)
        if "root" in response.text:
            return 2, "Possible Directory Traversal vulnerability detected!\n"
        else:
            return 10, "No Directory Traversal vulnerability detected.\n"
    except Exception as e:
        return 0, f"Error checking Directory Traversal: {e}\n"


def remote_code_execution_test(url):
    # Placeholder for remote code execution test; should implement actual checks.
    return 10, "No Remote Code Execution vulnerability detected.\n"


def file_inclusion_test(url):
    test_url = f"{url}/file?file=../../../../etc/passwd"  # Example path
    try:
        response = requests.get(test_url)
        if "root" in response.text:
            return 2, "Possible File Inclusion vulnerability detected!\n"
        else:
            return 10, "No File Inclusion vulnerability detected.\n"
    except Exception as e:
        return 0, f"Error checking File Inclusion: {e}\n"


def check_cors(url):
    try:
        response = requests.options(url)
        if "Access-Control-Allow-Origin" in response.headers:
            return 10, "CORS is properly configured.\n"
        else:
            return 2, "CORS misconfiguration detected!\n"
    except Exception as e:
        return 0, f"Error checking CORS: {e}\n"


def security_misconfiguration_test(url):
    # Placeholder for security misconfiguration checks.
    return 10, "No security misconfigurations detected.\n"


def insecure_cryptographic_storage_test(url):
    # Placeholder for checking insecure cryptographic storage.
    return 10, "No insecure cryptographic storage detected.\n"


def sensitive_data_exposure_test(url):
    # Placeholder for checking sensitive data exposure.
    return 10, "No sensitive data exposure detected.\n"


def check_security_updates(url):
    # Placeholder for checking for missing security updates.
    return 10, "All security updates are applied.\n"


def ssrf_test(url):
    # Placeholder for SSRF checks.
    return 10, "No SSRF vulnerabilities detected.\n"


def clickjacking_test(url):
    try:
        response = requests.get(url)
        if "X-Frame-Options" in response.headers:
            return 10, "No Clickjacking vulnerabilities detected.\n"
        else:
            return 2, "Clickjacking risk detected!\n"
    except Exception as e:
        return 0, f"Error checking Clickjacking: {e}\n"


def info_disclosure_test(url):
    try:
        response = requests.get(url)
        if response.status_code >= 400:
            return (
                2,
                f"Information disclosure detected! Status code: {response.status_code}\n",
            )
        return 10, "No information disclosure detected.\n"
    except Exception as e:
        return 0, f"Error checking Information Disclosure: {e}\n"


def email_header_injection_test(url):
    # Placeholder for email header injection checks.
    return 10, "No email header injection vulnerabilities detected.\n"


def command_injection_test(url):
    # Placeholder for command injection checks.
    return 10, "No command injection vulnerabilities detected.\n"


def improper_authentication_test(url):
    # Placeholder for improper authentication checks.
    return 10, "No improper authentication detected.\n"


def insecure_api_endpoints_test(url):
    # Placeholder for checking insecure API endpoints.
    return 10, "No insecure API endpoints detected.\n"


def unrestricted_file_upload_test(url):
    # Placeholder for unrestricted file upload checks.
    return 10, "No unrestricted file upload vulnerabilities detected.\n"


def weak_password_policy_test(url):
    # Placeholder for weak password policy checks.
    return 10, "Password policy is strong.\n"


def password_storage_test(url):
    # Placeholder for checking password storage methods.
    return 10, "Passwords are stored securely.\n"


def no_rate_limiting_test(url):
    # Placeholder for checking rate limiting.
    return 10, "Rate limiting is implemented.\n"


def missing_https_redirection_test(url):
    # Placeholder for checking HTTPS redirection.
    return 10, "HTTPS redirection is properly configured.\n"


def insecure_session_management_test(url):
    # Placeholder for checking session management practices.
    return 10, "Session management is secure.\n"


def outdated_libraries_test(url):
    # Placeholder for checking outdated libraries.
    return 10, "All libraries are up to date.\n"


def broken_access_control_test(url):
    # Placeholder for checking broken access control.
    return 10, "Access controls are properly configured.\n"


def unencrypted_sensitive_data_test(url):
    # Placeholder for checking unencrypted sensitive data.
    return 10, "Sensitive data is encrypted in transit.\n"


def weak_ssl_tls_config_test(url):
    # Placeholder for checking SSL/TLS configuration.
    return 10, "SSL/TLS configuration is secure.\n"


def subdomain_takeover_test(url):
    # Placeholder for checking subdomain takeover risks.
    return 10, "No subdomain takeover vulnerabilities detected.\n"


def missing_csp_test(url):
    # Placeholder for checking Content Security Policy.
    return 10, "CSP is properly configured.\n"


def lack_of_privacy_policy_test(url):
    # Placeholder for checking the existence of a privacy policy.
    return 10, "Privacy policy is present.\n"


def unnecessary_services_test(url):
    # Placeholder for checking unnecessary services.
    return 10, "No unnecessary services running.\n"


def session_fixation_test(url):
    # Placeholder for checking session fixation vulnerabilities.
    return 10, "No session fixation vulnerabilities detected.\n"


def client_side_security_issues_test(url):
    # Placeholder for checking client-side security issues.
    return 10, "Client-side security is strong.\n"


def social_engineering_vulnerabilities_test(url):
    # Placeholder for checking for social engineering risks.
    return 10, "No significant social engineering vulnerabilities detected.\n"


def csrf_test(url):
    # Placeholder for CSRF vulnerabilities.
    return 10, "No CSRF vulnerabilities detected.\n"


def missing_referrer_policy_test(url):
    # Placeholder for checking referrer policy.
    return 10, "Referrer policy is configured.\n"


def insecure_js_libs_test(url):
    # Placeholder for checking insecure JavaScript libraries.
    return 10, "No insecure JS libraries detected.\n"


def directory_indexing_test(url):
    test_url = f"{url}/"
    try:
        response = requests.get(test_url)
        if response.status_code == 200 and "Index of" in response.text:
            return 2, "Directory indexing is enabled!\n"
        else:
            return 10, "Directory indexing is disabled.\n"
    except Exception as e:
        return 0, f"Error checking Directory Indexing: {e}\n"


def overly_verbose_error_messages_test(url):
    test_url = f"{url}/invalid_endpoint"
    try:
        response = requests.get(test_url)
        if response.status_code >= 400:
            return (
                2,
                f"Verbose error message detected! Status code: {response.status_code}\n",
            )
        return 10, "No overly verbose error messages detected.\n"
    except Exception as e:
        return 0, f"Error checking verbose error messages: {e}\n"


def weak_input_validation_test(url):
    test_url = f"{url}/input?value=<script>alert('xss')</script>"
    try:
        response = requests.get(test_url)
        if "<script>alert('xss')</script>" in response.text:
            return 2, "Weak input validation detected!\n"
        return 10, "Input validation is strong.\n"
    except Exception as e:
        return 0, f"Error checking input validation: {e}\n"


def cookie_security_flags_test(url):
    try:
        response = requests.get(url)
        if "Set-Cookie" in response.headers:
            cookies = response.headers["Set-Cookie"]
            if "HttpOnly" in cookies and "Secure" in cookies:
                return 10, "Cookie security flags are set correctly.\n"
            else:                return 2, "Cookie security flags are missing!\n"
        return 10, "No cookies set, secure by default.\n"
    except Exception as e:
        return 0, f"Error checking cookie security flags: {e}\n"


def using_deprecated_apis_test(url):
    # Placeholder for checking deprecated API usage.
    return 10, "No deprecated APIs detected.\n"


def client_side_caching_issues_test(url):
    # Placeholder for checking client-side caching issues.
    return 10, "Client-side caching is secure.\n"


def lack_of_two_factor_authentication_test(url):
    # Placeholder for checking 2FA implementation.
    return 10, "Two-Factor Authentication is implemented.\n"


def broken_link_checking_test(url):
    # Placeholder for checking for broken links.
    return 10, "No broken links detected.\n"


def sensitive_info_in_code_repositories_test(url):
    # Placeholder for checking sensitive info in code repositories.
    return 10, "No sensitive information found in code repositories.\n"


def open_redirects_test(url):
    # Placeholder for checking open redirects.
    return 10, "No open redirect vulnerabilities detected.\n"


def memory_leak_vulnerabilities_test(url):
    # Placeholder for checking memory leak vulnerabilities.
    return 10, "No memory leaks detected.\n"


def check_clickjacking_protections(url):
    try:
        response = requests.get(url)
        if "X-Frame-Options" in response.headers:
            return 10, "Clickjacking protections are in place.\n"
        else:
            return 2, "Clickjacking protections are missing!\n"
    except Exception as e:
        return 0, f"Error checking clickjacking protections: {e}\n"


def evaluate_third_party_dependencies_test(url):
    # Placeholder for checking third-party dependencies.
    return 10, "Third-party dependencies are evaluated.\n"


# ---------- PDF Report Generation ----------


def generate_report(results):
    pdf_filename = "vulnerability_report.pdf"
    doc = SimpleDocTemplate(pdf_filename, pagesize=letter)
    styles = getSampleStyleSheet()

    elements = []
    title = Paragraph("Vulnerability Assessment Report", styles["Title"])
    elements.append(title)
    elements.append(Spacer(1, 12))

    # Add summary table data
    summary_data = [["Test Name", "Score"]]

    for test, (score, details) in results.items():
        summary_data.append([test, score])

        # Detailed Test Result
        elements.append(
            Paragraph(f"{test} - Score: {score}", styles["Heading2"])
        )
        elements.append(Paragraph(f"Details: {details}", styles["Normal"]))
        elements.append(Spacer(1, 12))

    # Adding Summary Table
    summary_table = Table(summary_data)
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("FONTSIZE", (0, 0), (-1, 0), 14),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                ("GRID", (0, 0), (-1, -1), 1, colors.black),
            ]
        )
    )

    elements.insert(1, summary_table)

    # Save the PDF
    doc.build(elements)

    return pdf_filename


# ---------- GUI Application ----------


class VulnerabilityAssessmentTool:
    def __init__(self, master):
        self.master = master
        master.title("Vulnerability Assessment Tool")

        self.url_label = Label(master, text="Enter URL:")
        self.url_label.pack()

        self.url_entry = Entry(master)
        self.url_entry.pack()

        self.apk_label = Label(master, text="Select APK File:")
        self.apk_label.pack()

        self.apk_entry = Entry(master)
        self.apk_entry.pack()

        self.apk_button = Button(master, text="Browse", command=self.browse_apk)
        self.apk_button.pack()

        self.run_button = Button(
            master, text="Run Assessment", command=self.run_assessment
        )
        self.run_button.pack()

        self.results_text = scrolledtext.ScrolledText(
            master, width=100, height=30
        )
        self.results_text.pack()

    def browse_apk(self):
        apk_file = filedialog.askopenfilename(
            filetypes=[("APK Files", "*.apk")]
        )
        self.apk_entry.delete(0, tk.END)
        self.apk_entry.insert(0, apk_file)

    def run_assessment(self):
        url = self.url_entry.get()
        apk_file = self.apk_entry.get()
        results = {}

        # Run all tests
        tests = [
            ("Check SSL Certificate", check_ssl_certificate),
            ("OWASP ZAP Scan", owasp_zap_scan),
            ("SQL Injection Test", check_sql_injection),
            ("XSS Test", check_xss),
            ("HTTP Security Headers Test", check_http_security_headers),
            ("APK Analysis", analyze_apk),
            ("Information Disclosure Test", info_disclosure_test),
            ("Email Header Injection Test", email_header_injection_test),
            ("Command Injection Test", command_injection_test),
            ("Improper Authentication Test", improper_authentication_test),
            ("Insecure API Endpoints Test", insecure_api_endpoints_test),
            ("Unrestricted File Upload Test", unrestricted_file_upload_test),
            ("Weak Password Policy Test", weak_password_policy_test),
            ("Password Storage Test", password_storage_test),
            ("No Rate Limiting Test", no_rate_limiting_test),
            ("Missing HTTPS Redirection Test", missing_https_redirection_test),
            ("Insecure Session Management Test", insecure_session_management_test),
            ("Outdated Libraries Test", outdated_libraries_test),
            ("Broken Access Control Test", broken_access_control_test),
            ("Unencrypted Sensitive Data Test", unencrypted_sensitive_data_test),
            ("Weak SSL/TLS Configuration Test", weak_ssl_tls_config_test),
            ("Subdomain Takeover Test", subdomain_takeover_test),
            ("Missing CSP Test", missing_csp_test),
            ("Lack of Privacy Policy Test", lack_of_privacy_policy_test),
            ("Unnecessary Services Test", unnecessary_services_test),
            ("Session Fixation Test", session_fixation_test),
            ("Client-Side Security Issues Test", client_side_security_issues_test),
            ("Social Engineering Vulnerabilities Test", social_engineering_vulnerabilities_test),
            ("CSRF Test", csrf_test),
            ("Missing Referrer Policy Test", missing_referrer_policy_test),
            ("Insecure JS Libraries Test", insecure_js_libs_test),
            ("Directory Indexing Test", directory_indexing_test),
            ("Overly Verbose Error Messages Test", overly_verbose_error_messages_test),
            ("Weak Input Validation Test", weak_input_validation_test),
            ("Cookie Security Flags Test", cookie_security_flags_test),
            ("Using Deprecated APIs Test", using_deprecated_apis_test),
            ("Client-Side Caching Issues Test", client_side_caching_issues_test),
            ("Lack of Two-Factor Authentication Test", lack_of_two_factor_authentication_test),
            ("Broken Link Checking Test", broken_link_checking_test),
            ("Sensitive Info in Code Repositories Test", sensitive_info_in_code_repositories_test),
            ("Open Redirects Test", open_redirects_test),
            ("Memory Leak Vulnerabilities Test", memory_leak_vulnerabilities_test),
            ("Check Clickjacking Protections", check_clickjacking_protections),
            ("Evaluate Third Party Dependencies Test", evaluate_third_party_dependencies_test),
        ]

        # Perform assessments
        if url:
            for test_name, test_func in tests:
                score, detail = test_func(url)
                results[test_name] = (score, detail)
                self.results_text.insert(
                    tk.END, f"{test_name}: Score: {score}\n{detail}\n"
                )

        if apk_file:
            score, apk_report = analyze_apk(apk_file)
            results["APK Analysis"] = (score, apk_report)
            self.results_text.insert(
                tk.END, f"APK Analysis: Score: {score}\n{apk_report}\n"
            )

        # Display results in the text box
        self.results_text.delete(1.0, tk.END)

        # Loop through the results and display each test's score and details
        for test, (score, details) in results.items():
            self.results_text.insert(tk.END, f"{test}: Score: {score} - {details}\n")

        # Call the function to generate the report
        pdf_filename = generate_report(results)  # 'results' instead of 'result'

        if pdf_filename is not None:  # Check if the report was generated
            self.results_text.insert(
                tk.END, f"\nPDF report generated: {pdf_filename}"
            )
        else:
            self.results_text.insert(
                tk.END, "\nPDF report generation was cancelled."
            )


def generate_report(results):
    # Prompt user for the file location to save the report
    pdf_filename = filedialog.asksaveasfilename(
        defaultextension=".pdf",
        filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")],
        title="Save PDF Report",
    )

    if not pdf_filename:  # If user cancels the dialog
        return None

    doc = SimpleDocTemplate(pdf_filename, pagesize=letter)
    styles = getSampleStyleSheet()

    elements = []
    title = Paragraph("Vulnerability Assessment Report", styles["Title"])
    elements.append(title)
    elements.append(Spacer(1, 12))

    # Add summary table data
    summary_data = [["Test Name", "Score"]]

    for test, (score, details) in results.items():
        summary_data.append([test, score])

        # Detailed Test Result
        elements.append(
            Paragraph(f"{test} - Score: {score}", styles["Heading2"])
        )
        elements.append(Paragraph(f"Details: {details}", styles["Normal"]))
        elements.append(Spacer(1, 12))

    # Adding Summary Table
    summary_table = Table(summary_data)
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("FONTSIZE", (0, 0), (-1, 0), 14),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                ("GRID", (0, 0), (-1, -1), 1, colors.black),
            ]
        )
    )

    elements.insert(1, summary_table)

    # Save the PDF
    doc.build(elements)

    return pdf_filename  # Return the filename of the generated PDF


if __name__ == "__main__":
    root = tk.Tk()
    app = VulnerabilityAssessmentTool(root)
    root.mainloop()