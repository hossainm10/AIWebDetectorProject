"""
Output Module
=============
Handles formatting and exporting analysis results.

This module provides:
- JSON export with pretty printing
- CSV export for spreadsheet analysis
- HTML reports for viewing in browser
- Console output formatting
- Result summarization

Why separate output module?
- Consistent formatting across application
- Easy to add new export formats
- Separates presentation from logic
- Reusable formatting functions

Author: Your Name
Date: 2025
"""

import json
import csv
import os
from datetime import datetime
from pathlib import Path


class OutputFormatter:
    """
    Formats and exports analysis results in multiple formats.
    
    Supports:
    - JSON (detailed, machine-readable)
    - CSV (for Excel/spreadsheets)
    - HTML (human-readable reports)
    - Console (terminal output)
    
    Attributes:
        output_dir: Directory for saving files
        timestamp: Timestamp for unique filenames
    """
    
    def __init__(self, output_dir='reports'):
        """
        Initialize output formatter.
        
        Args:
            output_dir (str): Directory to save output files
        
        Example:
            formatter = OutputFormatter('reports')
            formatter.save_json(results, 'analysis_results.json')
        """
        self.output_dir = output_dir
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
    
    # =====================================================================
    # JSON OUTPUT
    # =====================================================================
    
    def save_json(self, data, filename=None, pretty=True):
        """
        Save data as JSON file.
        
        JSON is best for:
        - Preserving data structure
        - Machine processing
        - Nested data
        
        Args:
            data: Data to save (dict, list, etc.)
            filename (str): Output filename (optional)
            pretty (bool): Pretty-print with indentation
        
        Returns:
            str: Path to saved file
        
        Example:
            results = {'url': 'example.com', 'risk': 'HIGH'}
            formatter.save_json(results, 'report.json')
        """
        
        # Generate filename if not provided
        if filename is None:
            filename = f'analysis_{self.timestamp}.json'
        
        filepath = os.path.join(self.output_dir, filename)
        
        # Save with pretty printing or compact
        # indent=2: Each level indented 2 spaces
        # ensure_ascii=False: Allow Unicode characters
        with open(filepath, 'w', encoding='utf-8') as f:
            if pretty:
                json.dump(data, f, indent=2, ensure_ascii=False)
            else:
                json.dump(data, f, ensure_ascii=False)
        
        return filepath
    
    def format_json_string(self, data, pretty=True):
        """
        Format data as JSON string (without saving).
        
        Args:
            data: Data to format
            pretty (bool): Pretty-print
        
        Returns:
            str: JSON string
        
        Example:
            json_str = formatter.format_json_string(results)
            print(json_str)
        """
        if pretty:
            return json.dumps(data, indent=2, ensure_ascii=False)
        else:
            return json.dumps(data, ensure_ascii=False)
    
    # =====================================================================
    # CSV OUTPUT
    # =====================================================================
    
    def save_csv(self, data, filename=None, headers=None):
        """
        Save data as CSV file.
        
        CSV is best for:
        - Spreadsheet analysis (Excel, Google Sheets)
        - Tabular data
        - Simple data structures
        
        Args:
            data (list): List of dictionaries or list of lists
            filename (str): Output filename
            headers (list): Column headers (optional)
        
        Returns:
            str: Path to saved file
        
        Example:
            data = [
                {'url': 'example.com', 'risk': 'HIGH', 'score': 85},
                {'url': 'google.com', 'risk': 'SAFE', 'score': 5}
            ]
            formatter.save_csv(data, 'results.csv')
        """
        
        if not data:
            print("No data to save")
            return None
        
        # Generate filename if not provided
        if filename is None:
            filename = f'analysis_{self.timestamp}.csv'
        
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            # Determine if data is list of dicts or list of lists
            if isinstance(data[0], dict):
                # List of dictionaries
                # Use dict keys as headers if not provided
                if headers is None:
                    headers = data[0].keys()
                
                writer = csv.DictWriter(f, fieldnames=headers)
                writer.writeheader()
                writer.writerows(data)
            else:
                # List of lists
                writer = csv.writer(f)
                
                # Write headers if provided
                if headers:
                    writer.writerow(headers)
                
                # Write data
                writer.writerows(data)
        
        return filepath
    
    # =====================================================================
    # HTML OUTPUT
    # =====================================================================
    
    def save_html_report(self, analysis_result, filename=None):
        """
        Generate HTML report from analysis result.
        
        HTML is best for:
        - Human-readable reports
        - Visual presentation
        - Sharing with non-technical users
        
        Args:
            analysis_result (dict): Analysis results
            filename (str): Output filename
        
        Returns:
            str: Path to saved HTML file
        
        Example:
            formatter.save_html_report(analysis, 'report.html')
            # Opens in browser for viewing
        """
        
        if filename is None:
            filename = f'report_{self.timestamp}.html'
        
        filepath = os.path.join(self.output_dir, filename)
        
        # Generate HTML content
        html = self._generate_html(analysis_result)
        
        # Save to file
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return filepath
    
    def _generate_html(self, result):
        """
        Generate HTML content from analysis result.
        
        Args:
            result (dict): Analysis results
        
        Returns:
            str: HTML content
        """
        
        # Extract data
        url = result.get('url', 'Unknown')
        timestamp = result.get('timestamp', datetime.now().isoformat())
        
        # ML results
        ml_result = result.get('ml_detection', {})
        is_anomaly = ml_result.get('is_anomaly', False)
        ml_confidence = ml_result.get('confidence', 0)
        
        # Rule-based results
        rule_result = result.get('rule_analysis', {})
        risk_score = rule_result.get('risk_score', 0)
        risk_level = rule_result.get('risk_level', 'UNKNOWN')
        triggered_rules = rule_result.get('triggered_rules', [])
        
        # Final verdict
        verdict = result.get('final_verdict', 'UNKNOWN')
        
        # Determine colors based on risk
        risk_colors = {
            'SAFE': '#28a745',     # Green
            'LOW': '#ffc107',      # Yellow
            'MEDIUM': '#fd7e14',   # Orange
            'HIGH': '#dc3545'      # Red
        }
        verdict_color = risk_colors.get(risk_level, '#6c757d')
        
        # Build HTML
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Analysis Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 900px;
            margin: 40px auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .report {{
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            padding: 30px;
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid #007bff;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #555;
            margin-top: 30px;
        }}
        .url {{
            background: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            word-break: break-all;
            font-family: monospace;
        }}
        .verdict {{
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            margin: 20px 0;
            background: {verdict_color};
            color: white;
            font-size: 24px;
            font-weight: bold;
        }}
        .metric {{
            display: flex;
            justify-content: space-between;
            padding: 10px;
            border-bottom: 1px solid #eee;
        }}
        .metric:last-child {{
            border-bottom: none;
        }}
        .label {{
            font-weight: bold;
            color: #666;
        }}
        .value {{
            color: #333;
        }}
        .rule {{
            background: #f8f9fa;
            padding: 15px;
            margin: 10px 0;
            border-left: 4px solid #dc3545;
            border-radius: 4px;
        }}
        .rule-name {{
            font-weight: bold;
            color: #333;
        }}
        .rule-desc {{
            color: #666;
            margin: 5px 0;
        }}
        .severity-HIGH {{
            border-left-color: #dc3545;
        }}
        .severity-MEDIUM {{
            border-left-color: #fd7e14;
        }}
        .severity-LOW {{
            border-left-color: #ffc107;
        }}
        .timestamp {{
            color: #999;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="report">
        <h1>🛡️ Security Analysis Report</h1>
        
        <p class="timestamp">Generated: {timestamp}</p>
        
        <h2>Analyzed URL</h2>
        <div class="url">{url}</div>
        
        <div class="verdict">{verdict}</div>
        
        <h2>Analysis Summary</h2>
        <div class="metric">
            <span class="label">Risk Level:</span>
            <span class="value" style="color: {verdict_color};">{risk_level}</span>
        </div>
        <div class="metric">
            <span class="label">Risk Score:</span>
            <span class="value">{risk_score}/100</span>
        </div>
        <div class="metric">
            <span class="label">ML Anomaly Detected:</span>
            <span class="value">{'Yes' if is_anomaly else 'No'}</span>
        </div>
        <div class="metric">
            <span class="label">ML Confidence:</span>
            <span class="value">{ml_confidence:.1f}%</span>
        </div>
        <div class="metric">
            <span class="label">Rules Triggered:</span>
            <span class="value">{len(triggered_rules)}</span>
        </div>
        
        <h2>Triggered Security Rules</h2>
"""
        
        # Add triggered rules
        if triggered_rules:
            for rule in triggered_rules:
                severity = rule.get('severity', 'MEDIUM')
                html += f"""
        <div class="rule severity-{severity}">
            <div class="rule-name">{rule.get('name', 'Unknown')}</div>
            <div class="rule-desc">{rule.get('description', '')}</div>
            <div style="margin-top: 5px;">
                <span style="color: #666;">Severity:</span> {severity} |
                <span style="color: #666;">Score:</span> +{rule.get('risk_score', 0)}
            </div>
        </div>
"""
        else:
            html += "        <p>No security rules were triggered.</p>\n"
        
        # Close HTML
        html += """
    </div>
</body>
</html>
"""
        
        return html
    
    # =====================================================================
    # CONSOLE OUTPUT
    # =====================================================================
    
    def print_analysis_summary(self, analysis_result):
        """
        Print formatted analysis summary to console.
        
        Args:
            analysis_result (dict): Analysis results
        
        Example:
            formatter.print_analysis_summary(results)
        """
        
        print("\n" + "=" * 70)
        print("SECURITY ANALYSIS RESULTS")
        print("=" * 70)
        
        # URL
        url = analysis_result.get('url', 'Unknown')
        print(f"\nURL: {url}")
        
        # Final verdict
        verdict = analysis_result.get('final_verdict', 'UNKNOWN')
        print(f"\nFINAL VERDICT: {verdict}")
        
        # ML Detection
        print("\n" + "-" * 70)
        print("ML ANOMALY DETECTION")
        print("-" * 70)
        
        ml_result = analysis_result.get('ml_detection', {})
        print(f"  Anomaly Detected: {ml_result.get('is_anomaly', 'Unknown')}")
        print(f"  Confidence: {ml_result.get('confidence', 0):.1f}%")
        print(f"  Decision Score: {ml_result.get('decision_score', 0):.4f}")
        
        # Rule-Based Analysis
        print("\n" + "-" * 70)
        print("RULE-BASED ANALYSIS")
        print("-" * 70)
        
        rule_result = analysis_result.get('rule_analysis', {})
        print(f"  Risk Score: {rule_result.get('risk_score', 0)}/100")
        print(f"  Risk Level: {rule_result.get('risk_level', 'Unknown')}")
        print(f"  Rules Triggered: {rule_result.get('rule_count', 0)}")
        
        # Triggered rules
        triggered_rules = rule_result.get('triggered_rules', [])
        if triggered_rules:
            print(f"\n  Triggered Rules:")
            for i, rule in enumerate(triggered_rules, 1):
                print(f"\n    {i}. {rule.get('name', 'Unknown')} ({rule.get('severity', 'UNKNOWN')})")
                print(f"       {rule.get('description', '')}")
                print(f"       Score: +{rule.get('risk_score', 0)}")
        
        print("\n" + "=" * 70)
    
    def print_batch_summary(self, results_list):
        """
        Print summary of batch analysis results.
        
        Args:
            results_list (list): List of analysis results
        
        Example:
            all_results = []
            for url in urls:
                result = analyze(url)
                all_results.append(result)
            
            formatter.print_batch_summary(all_results)
        """
        
        print("\n" + "=" * 70)
        print("BATCH ANALYSIS SUMMARY")
        print("=" * 70)
        
        # Count by verdict
        verdicts = {}
        for result in results_list:
            verdict = result.get('final_verdict', 'UNKNOWN')
            verdicts[verdict] = verdicts.get(verdict, 0) + 1
        
        # Print stats
        print(f"\nTotal URLs Analyzed: {len(results_list)}")
        print(f"\nBreakdown by Verdict:")
        for verdict, count in sorted(verdicts.items()):
            percentage = (count / len(results_list)) * 100
            print(f"  {verdict:15} {count:3} ({percentage:.1f}%)")
        
        # Print high-risk URLs
        high_risk = [r for r in results_list if r.get('rule_analysis', {}).get('risk_level') == 'HIGH']
        if high_risk:
            print(f"\nHigh Risk URLs ({len(high_risk)}):")
            for result in high_risk:
                url = result.get('url', 'Unknown')
                score = result.get('rule_analysis', {}).get('risk_score', 0)
                print(f"  • {url} (score: {score})")
        
        print("\n" + "=" * 70)


# =========================================================================
# CONVENIENCE FUNCTIONS
# =========================================================================

def save_results(data, filename, format='json', output_dir='reports'):
    """
    Quick function to save results.
    
    Args:
        data: Data to save
        filename (str): Output filename
        format (str): Format ('json', 'csv', 'html')
        output_dir (str): Output directory
    
    Returns:
        str: Path to saved file
    
    Example:
        save_results(results, 'analysis.json', format='json')
    """
    formatter = OutputFormatter(output_dir)
    
    if format == 'json':
        return formatter.save_json(data, filename)
    elif format == 'csv':
        return formatter.save_csv(data, filename)
    elif format == 'html':
        return formatter.save_html_report(data, filename)
    else:
        raise ValueError(f"Unsupported format: {format}")


# =========================================================================
# TEST CODE
# =========================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("OUTPUT MODULE - TEST MODE")
    print("=" * 70)
    
    formatter = OutputFormatter('test_reports')
    
    # Sample analysis result
    test_result = {
        'url': 'https://suspicious-site.xyz/login',
        'timestamp': datetime.now().isoformat(),
        'ml_detection': {
            'is_anomaly': True,
            'confidence': 87.5,
            'decision_score': -0.2453
        },
        'rule_analysis': {
            'risk_score': 85,
            'risk_level': 'HIGH',
            'rule_count': 3,
            'triggered_rules': [
                {
                    'name': 'Suspicious TLD',
                    'description': 'URL uses uncommon top-level domain',
                    'risk_score': 50,
                    'severity': 'HIGH'
                },
                {
                    'name': 'High Entropy URL',
                    'description': 'URL appears randomly generated',
                    'risk_score': 35,
                    'severity': 'MEDIUM'
                }
            ]
        },
        'final_verdict': 'MALICIOUS - High Confidence'
    }
    
    # Test 1: Console output
    print("\n[TEST 1] Console Output")
    print("-" * 70)
    formatter.print_analysis_summary(test_result)
    
    # Test 2: JSON export
    print("\n[TEST 2] JSON Export")
    print("-" * 70)
    json_file = formatter.save_json(test_result, 'test_analysis.json')
    print(f"✓ Saved to: {json_file}")
    
    # Test 3: HTML report
    print("\n[TEST 3] HTML Report")
    print("-" * 70)
    html_file = formatter.save_html_report(test_result, 'test_report.html')
    print(f"✓ Saved to: {html_file}")
    print(f"  Open in browser to view")
    
    # Test 4: CSV export
    print("\n[TEST 4] CSV Export")
    print("-" * 70)
    csv_data = [
        {'url': 'site1.com', 'risk': 'HIGH', 'score': 85},
        {'url': 'site2.com', 'risk': 'SAFE', 'score': 5},
        {'url': 'site3.com', 'risk': 'MEDIUM', 'score': 45}
    ]
    csv_file = formatter.save_csv(csv_data, 'test_results.csv')
    print(f"✓ Saved to: {csv_file}")
    
    # Test 5: Batch summary
    print("\n[TEST 5] Batch Summary")
    print("-" * 70)
    batch_results = [test_result.copy() for _ in range(5)]
    batch_results[0]['final_verdict'] = 'SAFE'
    batch_results[1]['final_verdict'] = 'SUSPICIOUS - Medium Confidence'
    
    formatter.print_batch_summary(batch_results)
    
    print("\n" + "=" * 70)
    print("✓ All tests complete!")
    print(f"✓ Test files saved in: test_reports/")
    print("=" * 70)