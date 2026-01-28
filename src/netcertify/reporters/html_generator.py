"""
HTML Report Generator - Create interactive certification reports.

Generates professional HTML reports from Pydantic result models.
Reports are standalone single-file HTML with embedded CSS and JavaScript.
"""

import os
import json
from datetime import datetime
from typing import Optional
from pathlib import Path

from netcertify.schemas.results import (
    CertificationReport,
    CertificationSuiteResult,
    TestResult,
    AssertionResult,
    ResultStatus,
    Severity,
)


# Inline HTML template for single-file reports
REPORT_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <style>
        :root {
            --color-success: #10b981;
            --color-failure: #ef4444;
            --color-warning: #f59e0b;
            --color-info: #3b82f6;
            --color-skipped: #6b7280;
            --color-bg: #0f172a;
            --color-bg-secondary: #1e293b;
            --color-bg-tertiary: #334155;
            --color-text: #e2e8f0;
            --color-text-muted: #94a3b8;
            --color-border: #475569;
            --color-accent: #8b5cf6;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: var(--color-bg);
            color: var(--color-text);
            line-height: 1.6;
            min-height: 100vh;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        /* Header */
        .header {
            background: linear-gradient(135deg, var(--color-bg-secondary) 0%, var(--color-bg-tertiary) 100%);
            border-radius: 16px;
            padding: 2rem;
            margin-bottom: 2rem;
            border: 1px solid var(--color-border);
        }
        
        .header-top {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            flex-wrap: wrap;
            gap: 1rem;
        }
        
        .header h1 {
            font-size: 2rem;
            font-weight: 700;
            color: var(--color-text);
            margin-bottom: 0.5rem;
        }
        
        .header .subtitle {
            color: var(--color-text-muted);
            font-size: 0.95rem;
        }
        
        .status-badge {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.75rem 1.5rem;
            border-radius: 50px;
            font-weight: 600;
            font-size: 1.1rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        
        .status-badge.passed {
            background: rgba(16, 185, 129, 0.2);
            color: var(--color-success);
            border: 2px solid var(--color-success);
        }
        
        .status-badge.failed {
            background: rgba(239, 68, 68, 0.2);
            color: var(--color-failure);
            border: 2px solid var(--color-failure);
        }
        
        .status-badge.warning {
            background: rgba(245, 158, 11, 0.2);
            color: var(--color-warning);
            border: 2px solid var(--color-warning);
        }
        
        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin: 2rem 0;
        }
        
        .stat-card {
            background: var(--color-bg-secondary);
            border-radius: 12px;
            padding: 1.5rem;
            border: 1px solid var(--color-border);
            text-align: center;
        }
        
        .stat-card .value {
            font-size: 2.5rem;
            font-weight: 700;
            color: var(--color-text);
        }
        
        .stat-card .value.success { color: var(--color-success); }
        .stat-card .value.failure { color: var(--color-failure); }
        .stat-card .value.accent { color: var(--color-accent); }
        
        .stat-card .label {
            color: var(--color-text-muted);
            font-size: 0.9rem;
            margin-top: 0.5rem;
        }
        
        /* Progress Bar */
        .progress-container {
            margin: 1.5rem 0;
        }
        
        .progress-bar {
            height: 12px;
            background: var(--color-bg-tertiary);
            border-radius: 6px;
            overflow: hidden;
        }
        
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--color-success), var(--color-accent));
            transition: width 0.5s ease;
        }
        
        .progress-label {
            display: flex;
            justify-content: space-between;
            margin-top: 0.5rem;
            font-size: 0.85rem;
            color: var(--color-text-muted);
        }
        
        /* Sections */
        .section {
            background: var(--color-bg-secondary);
            border-radius: 16px;
            margin-bottom: 2rem;
            border: 1px solid var(--color-border);
            overflow: hidden;
        }
        
        .section-header {
            background: var(--color-bg-tertiary);
            padding: 1rem 1.5rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            user-select: none;
        }
        
        .section-header:hover {
            background: rgba(75, 85, 99, 0.5);
        }
        
        .section-header h2 {
            font-size: 1.1rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        
        .section-content {
            padding: 1.5rem;
        }
        
        .section-content.collapsed {
            display: none;
        }
        
        /* Test Results */
        .test-item {
            background: var(--color-bg);
            border-radius: 8px;
            margin-bottom: 1rem;
            border: 1px solid var(--color-border);
            overflow: hidden;
        }
        
        .test-header {
            padding: 1rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
        }
        
        .test-header:hover {
            background: var(--color-bg-tertiary);
        }
        
        .test-name {
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }
        
        .test-meta {
            display: flex;
            gap: 1rem;
            color: var(--color-text-muted);
            font-size: 0.85rem;
        }
        
        .test-details {
            padding: 1rem;
            background: var(--color-bg-tertiary);
            border-top: 1px solid var(--color-border);
        }
        
        .test-details.hidden {
            display: none;
        }
        
        /* Assertion Table */
        .assertion-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
        }
        
        .assertion-table th {
            text-align: left;
            padding: 0.75rem;
            background: var(--color-bg);
            color: var(--color-text-muted);
            font-weight: 500;
            border-bottom: 1px solid var(--color-border);
        }
        
        .assertion-table td {
            padding: 0.75rem;
            border-bottom: 1px solid var(--color-border);
        }
        
        .assertion-table tr:last-child td {
            border-bottom: none;
        }
        
        .assertion-table tr:hover {
            background: rgba(255, 255, 255, 0.02);
        }
        
        /* Status Indicators */
        .status-icon {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 24px;
            height: 24px;
            border-radius: 50%;
            font-size: 0.75rem;
        }
        
        .status-icon.passed {
            background: rgba(16, 185, 129, 0.2);
            color: var(--color-success);
        }
        
        .status-icon.failed {
            background: rgba(239, 68, 68, 0.2);
            color: var(--color-failure);
        }
        
        .status-icon.skipped {
            background: rgba(107, 114, 128, 0.2);
            color: var(--color-skipped);
        }
        
        .severity-badge {
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .severity-badge.critical {
            background: rgba(239, 68, 68, 0.2);
            color: var(--color-failure);
        }
        
        .severity-badge.high {
            background: rgba(245, 158, 11, 0.2);
            color: var(--color-warning);
        }
        
        .severity-badge.medium {
            background: rgba(59, 130, 246, 0.2);
            color: var(--color-info);
        }
        
        .severity-badge.low {
            background: rgba(107, 114, 128, 0.2);
            color: var(--color-text-muted);
        }
        
        /* Critical Findings */
        .finding-card {
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid var(--color-failure);
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 1rem;
        }
        
        .finding-card h4 {
            color: var(--color-failure);
            margin-bottom: 0.5rem;
        }
        
        .finding-card p {
            color: var(--color-text-muted);
            font-size: 0.9rem;
        }
        
        .finding-card .remediation {
            margin-top: 0.75rem;
            padding: 0.75rem;
            background: var(--color-bg);
            border-radius: 4px;
            font-size: 0.85rem;
        }
        
        /* Executive Summary */
        .summary-text {
            white-space: pre-line;
            background: var(--color-bg);
            padding: 1.5rem;
            border-radius: 8px;
            font-size: 0.95rem;
            line-height: 1.8;
        }
        
        /* Footer */
        .footer {
            text-align: center;
            padding: 2rem;
            color: var(--color-text-muted);
            font-size: 0.85rem;
        }
        
        /* Utilities */
        .toggle-icon {
            transition: transform 0.2s;
        }
        
        .toggle-icon.collapsed {
            transform: rotate(-90deg);
        }
        
        .mono {
            font-family: 'SF Mono', 'Fira Code', monospace;
        }
        
        /* Animations */
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .section {
            animation: fadeIn 0.3s ease;
        }
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div class="header-top">
                <div>
                    <h1>{{ title }}</h1>
                    <p class="subtitle">Generated: {{ generated_at }} | Report ID: {{ report_id }}</p>
                </div>
                <span class="status-badge {{ overall_status_class }}">
                    {{ overall_status }}
                </span>
            </div>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="value accent">{{ total_devices }}</div>
                    <div class="label">Devices Tested</div>
                </div>
                <div class="stat-card">
                    <div class="value">{{ total_tests }}</div>
                    <div class="label">Total Tests</div>
                </div>
                <div class="stat-card">
                    <div class="value success">{{ passed_tests }}</div>
                    <div class="label">Passed</div>
                </div>
                <div class="stat-card">
                    <div class="value failure">{{ failed_tests }}</div>
                    <div class="label">Failed</div>
                </div>
                <div class="stat-card">
                    <div class="value">{{ total_assertions }}</div>
                    <div class="label">Assertions</div>
                </div>
            </div>
            
            <div class="progress-container">
                <div class="progress-bar">
                    <div class="progress-fill" style="width: {{ pass_rate }}%"></div>
                </div>
                <div class="progress-label">
                    <span>Pass Rate</span>
                    <span>{{ pass_rate }}%</span>
                </div>
            </div>
        </header>
        
        {{ executive_summary_section }}
        
        {{ critical_findings_section }}
        
        {{ test_results_section }}
        
        <footer class="footer">
            <p>Generated by NetCertify v{{ version }} | {{ organization }}</p>
        </footer>
    </div>
    
    <script>
        // Toggle section visibility
        document.querySelectorAll('.section-header').forEach(header => {
            header.addEventListener('click', () => {
                const content = header.nextElementSibling;
                const icon = header.querySelector('.toggle-icon');
                content.classList.toggle('collapsed');
                icon?.classList.toggle('collapsed');
            });
        });
        
        // Toggle test details
        document.querySelectorAll('.test-header').forEach(header => {
            header.addEventListener('click', () => {
                const details = header.nextElementSibling;
                const icon = header.querySelector('.toggle-icon');
                details.classList.toggle('hidden');
                icon?.classList.toggle('collapsed');
            });
        });
    </script>
</body>
</html>'''


class HTMLReportGenerator:
    """
    Generate interactive HTML reports from certification results.
    
    Reports are standalone single-file HTML documents with embedded
    CSS and JavaScript for a professional, interactive experience.
    
    Usage:
        generator = HTMLReportGenerator()
        html = generator.generate(report)
        generator.save(report, "output/certification_report.html")
    """
    
    def __init__(self, template: Optional[str] = None):
        """
        Initialize the report generator.
        
        Args:
            template: Optional custom HTML template
        """
        self.template = template or REPORT_TEMPLATE
    
    def generate(self, report: CertificationReport) -> str:
        """
        Generate HTML report from a CertificationReport model.
        
        Args:
            report: The certification report to render
            
        Returns:
            Complete HTML document as string
        """
        # Ensure aggregates are calculated
        report.calculate_aggregates()
        
        # Generate executive summary if not present
        if not report.executive_summary:
            report.generate_executive_summary()
        
        # Build template variables
        variables = {
            "title": report.metadata.report_title,
            "generated_at": report.metadata.generated_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "report_id": report.metadata.report_id,
            "overall_status": report.overall_status.value.upper(),
            "overall_status_class": self._status_class(report.overall_status),
            "total_devices": report.total_devices,
            "total_tests": report.total_tests,
            "passed_tests": report.passed_tests,
            "failed_tests": report.failed_tests,
            "total_assertions": report.total_assertions,
            "pass_rate": f"{report.overall_pass_rate:.1f}",
            "version": "1.0.0",
            "organization": report.metadata.organization or "NetCertify",
            "executive_summary_section": self._render_executive_summary(report),
            "critical_findings_section": self._render_critical_findings(report),
            "test_results_section": self._render_test_results(report),
        }
        
        # Simple template replacement
        html = self.template
        for key, value in variables.items():
            html = html.replace("{{ " + key + " }}", str(value))
        
        return html
    
    def save(self, report: CertificationReport, filepath: str) -> str:
        """
        Generate and save HTML report to file.
        
        Args:
            report: The certification report to render
            filepath: Output file path
            
        Returns:
            Absolute path to saved file
        """
        html = self.generate(report)
        
        # Ensure directory exists
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        # Write file
        path.write_text(html, encoding='utf-8')
        
        return str(path.absolute())
    
    def _status_class(self, status: ResultStatus) -> str:
        """Get CSS class for status."""
        mapping = {
            ResultStatus.PASSED: "passed",
            ResultStatus.FAILED: "failed",
            ResultStatus.WARNING: "warning",
            ResultStatus.ERROR: "failed",
            ResultStatus.SKIPPED: "skipped",
        }
        return mapping.get(status, "")
    
    def _severity_class(self, severity: Severity) -> str:
        """Get CSS class for severity."""
        return severity.value
    
    def _render_executive_summary(self, report: CertificationReport) -> str:
        """Render executive summary section."""
        return f'''
        <section class="section">
            <div class="section-header">
                <h2>
                    <span class="toggle-icon">▼</span>
                    Executive Summary
                </h2>
            </div>
            <div class="section-content">
                <div class="summary-text">{report.executive_summary}</div>
            </div>
        </section>
        '''
    
    def _render_critical_findings(self, report: CertificationReport) -> str:
        """Render critical findings section."""
        if not report.critical_findings:
            return ""
        
        findings_html = ""
        for finding in report.critical_findings:
            remediation = ""
            if finding.remediation:
                remediation = f'<div class="remediation"><strong>Remediation:</strong> {finding.remediation}</div>'
            
            findings_html += f'''
            <div class="finding-card">
                <h4>⚠️ {finding.name}</h4>
                <p><strong>Device:</strong> {finding.device_name or 'N/A'}</p>
                <p><strong>Expected:</strong> {finding.expected}</p>
                <p><strong>Actual:</strong> {finding.actual}</p>
                <p>{finding.message}</p>
                {remediation}
            </div>
            '''
        
        return f'''
        <section class="section">
            <div class="section-header">
                <h2>
                    <span class="toggle-icon">▼</span>
                    ⚠️ Critical Findings ({len(report.critical_findings)})
                </h2>
            </div>
            <div class="section-content">
                {findings_html}
            </div>
        </section>
        '''
    
    def _render_test_results(self, report: CertificationReport) -> str:
        """Render test results section."""
        suites_html = ""
        
        for suite in report.suites:
            tests_html = ""
            
            for test in suite.tests:
                # Render assertions table
                assertions_html = ""
                for assertion in test.all_assertions:
                    status_icon = "✓" if assertion.passed else "✗" if assertion.failed else "○"
                    status_class = self._status_class(assertion.status)
                    severity_class = self._severity_class(assertion.severity)
                    
                    assertions_html += f'''
                    <tr>
                        <td>
                            <span class="status-icon {status_class}">{status_icon}</span>
                        </td>
                        <td>{assertion.name}</td>
                        <td><span class="severity-badge {severity_class}">{assertion.severity.value}</span></td>
                        <td class="mono">{self._escape(str(assertion.expected))}</td>
                        <td class="mono">{self._escape(str(assertion.actual))}</td>
                        <td>{assertion.message}</td>
                    </tr>
                    '''
                
                test_status_class = self._status_class(test.status)
                test_icon = "✓" if test.status == ResultStatus.PASSED else "✗"
                
                tests_html += f'''
                <div class="test-item">
                    <div class="test-header">
                        <span class="test-name">
                            <span class="status-icon {test_status_class}">{test_icon}</span>
                            {test.name}
                        </span>
                        <div class="test-meta">
                            <span>{test.passed_assertions}/{test.total_assertions} assertions</span>
                            <span>{test.duration_ms:.0f}ms</span>
                            <span class="toggle-icon collapsed">▼</span>
                        </div>
                    </div>
                    <div class="test-details hidden">
                        <table class="assertion-table">
                            <thead>
                                <tr>
                                    <th width="40">Status</th>
                                    <th>Assertion</th>
                                    <th width="80">Severity</th>
                                    <th>Expected</th>
                                    <th>Actual</th>
                                    <th>Message</th>
                                </tr>
                            </thead>
                            <tbody>
                                {assertions_html}
                            </tbody>
                        </table>
                    </div>
                </div>
                '''
            
            suites_html += f'''
            <section class="section">
                <div class="section-header">
                    <h2>
                        <span class="toggle-icon">▼</span>
                        {suite.name} ({suite.passed_tests}/{suite.total_tests} passed)
                    </h2>
                </div>
                <div class="section-content">
                    {tests_html}
                </div>
            </section>
            '''
        
        return suites_html
    
    def _escape(self, text: str) -> str:
        """Escape HTML special characters."""
        if text is None:
            return ""
        text = str(text)
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
        )
