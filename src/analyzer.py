class RuleBasedAnalyzer:
    """
    Applies security rules to detect suspicious activity.
    
    This class implements a rule-based expert system. Each rule checks for
    a specific threat pattern and assigns a risk score. Rules are based on:
    - OWASP security guidelines
    - Anti-Phishing Working Group (APWG) research
    - Common phishing/malware patterns
    
    Attributes:
        risk_rules: List of rule dictionaries with conditions and scores
        risk_thresholds: Score ranges for risk levels (LOW, MEDIUM, HIGH)
    """
    
    def __init__(self):
        """
        Initialize the analyzer with security rules.
        
        Rules are stored as a list of dictionaries. Each rule has:
        - name: Human-readable rule name
        - condition: Function that checks if rule applies
        - risk_score: Points added if rule triggers (0-100)
        - severity: Importance level (LOW, MEDIUM, HIGH, CRITICAL)
        - description: What the rule detects
        """
        self.risk_rules = []
        
        # Define risk level thresholds
        # Total score determines overall risk level
        self.risk_thresholds = {
            'SAFE': (0, 19),      # 0-19 points
            'LOW': (20, 39),      # 20-39 points
            'MEDIUM': (40, 69),   # 40-69 points
            'HIGH': (70, 100)     # 70-100 points
        }
        
        # Initialize all security rules
        self._initialize_rules()
    
    def _initialize_rules(self):
        """
        Define all security rules.
        
        Each rule is a dictionary with:
        - name: Rule identifier
        - check: Lambda function that takes features dict and returns True/False
        - risk_score: Points if rule triggers
        - severity: Impact level
        - description: What was detected
        - recommendation: What user should do
        
        Rules are ordered from most to least severe.
        """
        
        # =====================================================================
        # CRITICAL SEVERITY RULES (70+ points)
        # These indicate high probability of phishing/malware
        # =====================================================================
        
        # RULE 1: Non-HTTPS Login Form
        # Why: Passwords sent in plain text over HTTP can be intercepted
        # Impact: CRITICAL - user credentials at risk
        self.risk_rules.append({
            'name': 'Insecure Login Form',
            'check': lambda f: f.get('has_login_form', 0) == 1 and f.get('is_https', 1) == 0,
            'risk_score': 80,
            'severity': 'CRITICAL',
            'description': 'Login form detected on non-HTTPS site',
            'recommendation': 'DO NOT enter credentials. Site is insecure.'
        })
        # Explanation of lambda:
        # lambda f: ... creates anonymous function that takes 'f' (features dict)
        # f.get('has_login_form', 0) gets value or returns 0 if key missing
        # == 1 checks if value is 1 (True)
        # 'and' combines two conditions
        
        # RULE 2: IP Address URL with Login
        # Why: Legitimate sites use domain names, not IP addresses
        # Impact: CRITICAL - almost certainly phishing
        self.risk_rules.append({
            'name': 'IP Address Login',
            'check': lambda f: f.get('has_ip_address', 0) == 1 and f.get('has_login_form', 0) == 1,
            'risk_score': 85,
            'severity': 'CRITICAL',
            'description': 'Login form on IP address URL (not a domain)',
            'recommendation': 'DANGER: Legitimate sites use domain names, not IPs'
        })
        
        # RULE 3: Phishing Language Pattern
        # Why: Phishers use urgency + sensitive words to manipulate victims
        # Impact: HIGH - common phishing tactic
        self.risk_rules.append({
            'name': 'Phishing Language Pattern',
            'check': lambda f: (
                f.get('sensitive_keyword_count', 0) >= 3 and 
                f.get('has_urgency_words', 0) == 1
            ),
            'risk_score': 70,
            'severity': 'HIGH',
            'description': 'Page uses phishing-like language (urgency + sensitive keywords)',
            'recommendation': 'Be extremely cautious. Verify site legitimacy.'
        })
        # Example: "URGENT: Your bank account has been suspended. Verify now!"
        
        # =====================================================================
        # HIGH SEVERITY RULES (40-69 points)
        # Strong indicators of suspicious activity
        # =====================================================================
        
        # RULE 4: Suspicious TLD
        # Why: Free/cheap TLDs are heavily used by scammers
        # Impact: HIGH - statistically correlated with phishing
        self.risk_rules.append({
            'name': 'Suspicious TLD',
            'check': lambda f: f.get('has_suspicious_tld', 0) == 1,
            'risk_score': 50,
            'severity': 'HIGH',
            'description': 'URL uses uncommon/suspicious top-level domain (.tk, .xyz, etc.)',
            'recommendation': 'Exercise caution. Verify site authenticity.'
        })
        # Examples: .tk (free), .ml (free), .xyz (cheap)
        
        # RULE 5: Hidden Form Elements
        # Why: Phishers hide elements to collect data without user knowing
        # Impact: HIGH - indicates deceptive practices
        self.risk_rules.append({
            'name': 'Hidden Form Elements',
            'check': lambda f: (
                f.get('has_hidden_elements', 0) == 1 and 
                f.get('form_count', 0) > 0
            ),
            'risk_score': 60,
            'severity': 'HIGH',
            'description': 'Form contains hidden elements',
            'recommendation': 'Site may be collecting data without disclosure'
        })
        
        # RULE 6: URL Shortener with Login
        # Why: Shorteners hide destination; legitimate sites don't hide login pages
        # Impact: HIGH - hides malicious destination
        self.risk_rules.append({
            'name': 'Shortened URL with Login',
            'check': lambda f: (
                f.get('is_url_shortener', 0) == 1 and 
                f.get('has_login_form', 0) == 1
            ),
            'risk_score': 65,
            'severity': 'HIGH',
            'description': 'Login form accessed via URL shortener',
            'recommendation': 'SUSPICIOUS: URL shorteners hide true destination'
        })
        
        # RULE 7: At Symbol Trick
        # Why: @ symbol in URL is a phishing technique to hide real domain
        # Impact: HIGH - deliberate deception
        self.risk_rules.append({
            'name': 'URL @ Symbol Trick',
            'check': lambda f: f.get('has_at_symbol', 0) == 1,
            'risk_score': 55,
            'severity': 'HIGH',
            'description': 'URL contains @ symbol (phishing technique)',
            'recommendation': 'TRICK: Browser ignores everything before @ symbol'
        })
        # Example: http://google.com@malicious.com actually goes to malicious.com
        
        # =====================================================================
        # MEDIUM SEVERITY RULES (20-39 points)
        # Potential issues that warrant attention
        # =====================================================================
        
        # RULE 8: High Entropy URL
        # Why: Random-looking URLs are often auto-generated by malware
        # Impact: MEDIUM - could be legitimate (some sites use random IDs)
        self.risk_rules.append({
            'name': 'High Entropy URL',
            'check': lambda f: f.get('entropy', 0) > 4.5,
            'risk_score': 35,
            'severity': 'MEDIUM',
            'description': 'URL appears randomly generated (high entropy)',
            'recommendation': 'Unusual URL structure. Verify site legitimacy.'
        })
        # High entropy example: https://x7k2m9p4b.com
        # Normal entropy example: https://google.com
        
        # RULE 9: Excessive Subdomains
        # Why: Phishers stuff keywords in subdomains to appear legitimate
        # Impact: MEDIUM - sometimes legitimate (corporate intranets)
        self.risk_rules.append({
            'name': 'Excessive Subdomains',
            'check': lambda f: f.get('subdomain_count', 0) >= 4,
            'risk_score': 30,
            'severity': 'MEDIUM',
            'description': 'Unusual number of subdomains in URL',
            'recommendation': 'Verify this is the correct domain'
        })
        # Example: secure.login.verify.account.paypal.com.phishing.xyz
        
        # RULE 10: Excessive External Scripts
        # Why: Too many external scripts indicates ad injection or tracking
        # Impact: MEDIUM - could be legitimate ad-heavy site
        self.risk_rules.append({
            'name': 'Excessive External Scripts',
            'check': lambda f: f.get('external_script_count', 0) > 10,
            'risk_score': 25,
            'severity': 'MEDIUM',
            'description': 'Unusual number of external scripts loaded',
            'recommendation': 'Site loads many external resources. Could indicate malicious activity.'
        })
        
        # RULE 11: Prize/Lottery Scam Language
        # Why: "You've won!" is classic scam tactic
        # Impact: MEDIUM - clear scam indicator but easy to spot
        self.risk_rules.append({
            'name': 'Prize Scam Language',
            'check': lambda f: f.get('has_prize_words', 0) == 1,
            'risk_score': 40,
            'severity': 'MEDIUM',
            'description': 'Page contains prize/lottery scam language',
            'recommendation': 'SCAM: Unsolicited prizes are always fake'
        })
        
        # RULE 12: Long URL
        # Why: Phishers stuff keywords to appear in search results
        # Impact: LOW-MEDIUM - some legitimate sites have long URLs
        self.risk_rules.append({
            'name': 'Abnormally Long URL',
            'check': lambda f: f.get('url_length', 0) > 100,
            'risk_score': 20,
            'severity': 'MEDIUM',
            'description': 'URL is abnormally long',
            'recommendation': 'Long URLs can indicate keyword stuffing'
        })
        
        # =====================================================================
        # LOW SEVERITY RULES (10-19 points)
        # Minor concerns, often false positives
        # =====================================================================
        
        # RULE 13: Many Dashes in Domain
        # Why: Dashes sometimes used to mimic brands
        # Impact: LOW - many legitimate sites use dashes
        self.risk_rules.append({
            'name': 'Multiple Dashes',
            'check': lambda f: f.get('dash_count', 0) >= 5,
            'risk_score': 15,
            'severity': 'LOW',
            'description': 'Domain contains many dashes',
            'recommendation': 'Verify this is the official domain'
        })
        # Example: pay-pal-secure.com (fake) vs paypal.com (real)
        
        # RULE 14: No Favicon
        # Why: Professional sites have favicons; phishing pages might not
        # Impact: LOW - many legitimate sites don't have favicons
        self.risk_rules.append({
            'name': 'Missing Favicon',
            'check': lambda f: f.get('has_favicon', 0) == 0 and f.get('form_count', 0) > 0,
            'risk_score': 10,
            'severity': 'LOW',
            'description': 'Site has forms but no favicon',
            'recommendation': 'Minor indicator: professional sites usually have favicons'
        })
        
        # RULE 15: Right-Click Disabled
        # Why: Sites that disable right-click might be hiding something
        # Impact: LOW - some legitimate sites do this (image protection)
        self.risk_rules.append({
            'name': 'Right-Click Disabled',
            'check': lambda f: f.get('disables_right_click', 0) == 1,
            'risk_score': 15,
            'severity': 'LOW',
            'description': 'Site disables right-click',
            'recommendation': 'Site is trying to prevent inspection. Be cautious.'
        })
    
    def analyze(self, features_dict):
        """
        Apply all rules and calculate total risk score.
        
        This is the main method that:
        1. Checks each rule against the features
        2. Collects triggered rules
        3. Sums up risk scores
        4. Determines overall risk level
        
        Args:
            features_dict (dict): Dictionary of features from FeatureCollector
                Example: {'has_login_form': 1, 'is_https': 0, ...}
        
        Returns:
            dict: Analysis results containing:
                - risk_score: Total points (0-100+)
                - risk_level: SAFE, LOW, MEDIUM, or HIGH
                - triggered_rules: List of rules that matched
                - rule_count: Number of rules triggered
                - recommendations: List of actions user should take
        
        Example:
            analyzer = RuleBasedAnalyzer()
            features = {'has_login_form': 1, 'is_https': 0, 'has_ip_address': 1}
            result = analyzer.analyze(features)
            
            print(result['risk_score'])  # 165 (very high!)
            print(result['risk_level'])  # HIGH
            print(len(result['triggered_rules']))  # 2 rules triggered
        """
        # Initialize results
        triggered_rules = []
        total_risk_score = 0
        recommendations = set()  # Use set to avoid duplicates
        
        # Check each rule
        print(f"Checking {len(self.risk_rules)} security rules...")
        
        for rule in self.risk_rules:
            try:
                # Call the rule's check function with features
                # rule['check'] is a lambda function
                # Example: lambda f: f.get('has_login_form') == 1
                if rule['check'](features_dict):
                    # Rule matched! Record it
                    triggered_rules.append({
                        'name': rule['name'],
                        'description': rule['description'],
                        'risk_score': rule['risk_score'],
                        'severity': rule['severity'],
                        'recommendation': rule['recommendation']
                    })
                    
                    # Add to total score
                    total_risk_score += rule['risk_score']
                    
                    # Collect recommendation
                    recommendations.add(rule['recommendation'])
                    
                    # Log which rule triggered (for debugging)
                    print(f"  ⚠ TRIGGERED: {rule['name']} (+{rule['risk_score']} points)")
            
            except KeyError as e:
                # Feature missing from features_dict
                # This can happen if feature extraction failed
                print(f"  Warning: Missing feature for rule '{rule['name']}': {e}")
                continue
            
            except Exception as e:
                # Unexpected error in rule check
                print(f"  Error checking rule '{rule['name']}': {e}")
                continue
        
        # Cap score at 100 for display purposes
        # (multiple high-severity rules can exceed 100)
        display_score = min(total_risk_score, 100)
        
        # Determine risk level based on score
        risk_level = self._calculate_risk_level(display_score)
        
        # Build result dictionary
        result = {
            'risk_score': display_score,
            'raw_score': total_risk_score,  # Uncapped score
            'risk_level': risk_level,
            'triggered_rules': triggered_rules,
            'rule_count': len(triggered_rules),
            'recommendations': list(recommendations),
            'severity_breakdown': self._get_severity_breakdown(triggered_rules)
        }
        
        return result
    
    def _calculate_risk_level(self, score):
        """
        Determine risk level from score.
        
        Args:
            score (int): Risk score (0-100)
        
        Returns:
            str: Risk level (SAFE, LOW, MEDIUM, HIGH)
        
        Example:
            _calculate_risk_level(15)  # 'SAFE'
            _calculate_risk_level(45)  # 'MEDIUM'
            _calculate_risk_level(85)  # 'HIGH'
        """
        for level, (min_score, max_score) in self.risk_thresholds.items():
            if min_score <= score <= max_score:
                return level
        
        # If score exceeds 100, it's definitely HIGH
        return 'HIGH'
    
    def _get_severity_breakdown(self, triggered_rules):
        """
        Count how many rules of each severity triggered.
        
        Args:
            triggered_rules (list): List of triggered rule dictionaries
        
        Returns:
            dict: Count of rules by severity
        
        Example:
            {'CRITICAL': 2, 'HIGH': 1, 'MEDIUM': 3, 'LOW': 0}
        """
        breakdown = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0
        }
        
        for rule in triggered_rules:
            severity = rule['severity']
            breakdown[severity] += 1
        
        return breakdown
    
    def get_rule_info(self, rule_name):
        """
        Get detailed information about a specific rule.
        
        Args:
            rule_name (str): Name of the rule
        
        Returns:
            dict: Rule information or None if not found
        
        Example:
            analyzer = RuleBasedAnalyzer()
            info = analyzer.get_rule_info('Insecure Login Form')
            print(info['description'])
            print(info['risk_score'])
        """
        for rule in self.risk_rules:
            if rule['name'] == rule_name:
                return {
                    'name': rule['name'],
                    'risk_score': rule['risk_score'],
                    'severity': rule['severity'],
                    'description': rule['description'],
                    'recommendation': rule['recommendation']
                }
        return None
    
    def list_all_rules(self):
        """
        Get summary of all rules.
        
        Returns:
            list: List of rule summaries
        
        Example:
            analyzer = RuleBasedAnalyzer()
            rules = analyzer.list_all_rules()
            for rule in rules:
                print(f"{rule['name']}: {rule['risk_score']} points")
        """
        return [
            {
                'name': rule['name'],
                'risk_score': rule['risk_score'],
                'severity': rule['severity']
            }
            for rule in self.risk_rules
        ]


# =========================================================================
# HELPER FUNCTIONS
# =========================================================================

def print_analysis_report(analysis_result):
    """
    Pretty-print analysis results.
    
    Args:
        analysis_result (dict): Output from RuleBasedAnalyzer.analyze()
    
    Example:
        result = analyzer.analyze(features)
        print_analysis_report(result)
    """
    print("\n" + "=" * 70)
    print("SECURITY ANALYSIS REPORT")
    print("=" * 70)
    
    # Risk score and level
    print(f"\nRisk Score: {analysis_result['risk_score']}/100")
    print(f"Risk Level: {analysis_result['risk_level']}")
    
    # Severity breakdown
    print(f"\nSeverity Breakdown:")
    breakdown = analysis_result['severity_breakdown']
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = breakdown[severity]
        if count > 0:
            print(f"  {severity}: {count} rule(s)")
    
    # Triggered rules
    print(f"\nTriggered Rules ({analysis_result['rule_count']}):")
    if analysis_result['triggered_rules']:
        for i, rule in enumerate(analysis_result['triggered_rules'], 1):
            print(f"\n  {i}. {rule['name']} ({rule['severity']})")
            print(f"     Score: +{rule['risk_score']}")
            print(f"     {rule['description']}")
            print(f"     → {rule['recommendation']}")
    else:
        print("  None - Site appears safe")
    
    # Recommendations
    if analysis_result['recommendations']:
        print(f"\nRecommendations:")
        for i, rec in enumerate(analysis_result['recommendations'], 1):
            print(f"  {i}. {rec}")
    
    print("\n" + "=" * 70)


# =========================================================================
# TEST CODE
# =========================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("RULE-BASED ANALYZER - TEST MODE")
    print("=" * 70)
    
    analyzer = RuleBasedAnalyzer()
    
    # ===== TEST 1: List All Rules =====
    print("\n[TEST 1] All Security Rules")
    print("-" * 70)
    
    rules = analyzer.list_all_rules()
    print(f"Total rules: {len(rules)}\n")
    
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        severity_rules = [r for r in rules if r['severity'] == severity]
        if severity_rules:
            print(f"\n{severity} Severity:")
            for rule in severity_rules:
                print(f"  • {rule['name']:30} {rule['risk_score']:3} points")
    
    # ===== TEST 2: Safe Website =====
    print("\n\n[TEST 2] Analyzing Safe Website")
    print("-" * 70)
    
    safe_features = {
        'url_length': 22,
        'is_https': 1,
        'has_ip_address': 0,
        'has_suspicious_tld': 0,
        'has_login_form': 0,
        'entropy': 2.5,
        'subdomain_count': 1,
        'external_script_count': 3,
        'has_urgency_words': 0,
        'has_prize_words': 0,
        'has_favicon': 1,
        'sensitive_keyword_count': 0
    }
    
    result = analyzer.analyze(safe_features)
    print_analysis_report(result)
    
    # ===== TEST 3: Phishing Website =====
    print("\n\n[TEST 3] Analyzing Phishing Website")
    print("-" * 70)
    
    phishing_features = {
        'url_length': 65,
        'is_https': 0,  # Non-HTTPS
        'has_ip_address': 1,  # IP address URL
        'has_suspicious_tld': 1,  # .xyz domain
        'has_login_form': 1,  # Has login
        'entropy': 4.8,  # High entropy
        'subdomain_count': 5,  # Many subdomains
        'external_script_count': 15,  # Many scripts
        'has_urgency_words': 1,  # "URGENT!"
        'has_prize_words': 0,
        'has_favicon': 0,
        'sensitive_keyword_count': 4,  # password, bank, verify, account
        'has_hidden_elements': 1,
        'has_at_symbol': 1
    }
    
    result = analyzer.analyze(phishing_features)
    print_analysis_report(result)
    
    # ===== TEST 4: Rule Lookup =====
    print("\n\n[TEST 4] Rule Information Lookup")
    print("-" * 70)
    
    rule_info = analyzer.get_rule_info('Insecure Login Form')
    if rule_info:
        print(f"Rule: {rule_info['name']}")
        print(f"Severity: {rule_info['severity']}")
        print(f"Score: {rule_info['risk_score']}")
        print(f"Description: {rule_info['description']}")
        print(f"Recommendation: {rule_info['recommendation']}")
    
    print("\n" + "=" * 70)
    print("✓ All tests complete!")
    print("=" * 70)