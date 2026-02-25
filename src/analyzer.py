class RuleBasedAnalyzer:
 
    
    def __init__(self):
       
        self.risk_rules = []
        
        
        self.risk_thresholds = {
            'SAFE': (0, 19),      
            'LOW': (20, 39),      
            'MEDIUM': (40, 69),   
            'HIGH': (70, 100)     
        }
        
        
        self._initialize_rules()
    
    def _initialize_rules(self):
        self.risk_rules.append({
            'name': 'Insecure Login Form',
            'check': lambda f: f.get('has_login_form', 0) == 1 and f.get('is_https', 1) == 0,
            'risk_score': 80,
            'severity': 'CRITICAL',
            'description': 'Login form detected on non-HTTPS site',
            'recommendation': 'DO NOT enter credentials. Site is insecure.'
        })
        self.risk_rules.append({
            'name': 'IP Address Login',
            'check': lambda f: f.get('has_ip_address', 0) == 1 and f.get('has_login_form', 0) == 1,
            'risk_score': 85,
            'severity': 'CRITICAL',
            'description': 'Login form on IP address URL (not a domain)',
            'recommendation': 'DANGER: Legitimate sites use domain names, not IPs'
        })
        
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
        self.risk_rules.append({
            'name': 'Suspicious TLD',
            'check': lambda f: f.get('has_suspicious_tld', 0) == 1,
            'risk_score': 50,
            'severity': 'HIGH',
            'description': 'URL uses uncommon/suspicious top-level domain (.tk, .xyz, etc.)',
            'recommendation': 'Exercise caution. Verify site authenticity.'
        })
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
        
        self.risk_rules.append({
            'name': 'URL @ Symbol Trick',
            'check': lambda f: f.get('has_at_symbol', 0) == 1,
            'risk_score': 55,
            'severity': 'HIGH',
            'description': 'URL contains @ symbol (phishing technique)',
            'recommendation': 'TRICK: Browser ignores everything before @ symbol'
        })
        self.risk_rules.append({
            'name': 'High Entropy URL',
            'check': lambda f: f.get('entropy', 0) > 4.5,
            'risk_score': 35,
            'severity': 'MEDIUM',
            'description': 'URL appears randomly generated (high entropy)',
            'recommendation': 'Unusual URL structure. Verify site legitimacy.'
        })
        self.risk_rules.append({
            'name': 'Excessive Subdomains',
            'check': lambda f: f.get('subdomain_count', 0) >= 4,
            'risk_score': 30,
            'severity': 'MEDIUM',
            'description': 'Unusual number of subdomains in URL',
            'recommendation': 'Verify this is the correct domain'
        })
        self.risk_rules.append({
            'name': 'Excessive External Scripts',
            'check': lambda f: f.get('external_script_count', 0) > 10,
            'risk_score': 25,
            'severity': 'MEDIUM',
            'description': 'Unusual number of external scripts loaded',
            'recommendation': 'Site loads many external resources. Could indicate malicious activity.'
        })
        
        self.risk_rules.append({
            'name': 'Prize Scam Language',
            'check': lambda f: f.get('has_prize_words', 0) == 1,
            'risk_score': 40,
            'severity': 'MEDIUM',
            'description': 'Page contains prize/lottery scam language',
            'recommendation': 'SCAM: Unsolicited prizes are always fake'
        })
        
        self.risk_rules.append({
            'name': 'Abnormally Long URL',
            'check': lambda f: f.get('url_length', 0) > 100,
            'risk_score': 20,
            'severity': 'MEDIUM',
            'description': 'URL is abnormally long',
            'recommendation': 'Long URLs can indicate keyword stuffing'
        })
        
        self.risk_rules.append({
            'name': 'Multiple Dashes',
            'check': lambda f: f.get('dash_count', 0) >= 5,
            'risk_score': 15,
            'severity': 'LOW',
            'description': 'Domain contains many dashes',
            'recommendation': 'Verify this is the official domain'
        })
        self.risk_rules.append({
            'name': 'Missing Favicon',
            'check': lambda f: f.get('has_favicon', 0) == 0 and f.get('form_count', 0) > 0,
            'risk_score': 10,
            'severity': 'LOW',
            'description': 'Site has forms but no favicon',
            'recommendation': 'Minor indicator: professional sites usually have favicons'
        })
        
        self.risk_rules.append({
            'name': 'Right-Click Disabled',
            'check': lambda f: f.get('disables_right_click', 0) == 1,
            'risk_score': 15,
            'severity': 'LOW',
            'description': 'Site disables right-click',
            'recommendation': 'Site is trying to prevent inspection. Be cautious.'
        })
    
    def analyze(self, features_dict):
        triggered_rules = []
        total_risk_score = 0
        recommendations = set() 
        
        print(f"Checking {len(self.risk_rules)} security rules...")
        
        for rule in self.risk_rules:
            try:
                if rule['check'](features_dict):
                    triggered_rules.append({
                        'name': rule['name'],
                        'description': rule['description'],
                        'risk_score': rule['risk_score'],
                        'severity': rule['severity'],
                        'recommendation': rule['recommendation']
                    })
                    
                    total_risk_score += rule['risk_score']
                    
                    recommendations.add(rule['recommendation'])
                    
                    print(f"  ⚠ TRIGGERED: {rule['name']} (+{rule['risk_score']} points)")
            
            except KeyError as e:
                print(f"  Warning: Missing feature for rule '{rule['name']}': {e}")
                continue
            
            except Exception as e:
                print(f"  Error checking rule '{rule['name']}': {e}")
                continue
        
        display_score = min(total_risk_score, 100)
        
        risk_level = self._calculate_risk_level(display_score)
        
        result = {
            'risk_score': display_score,
            'raw_score': total_risk_score, # Uncapped score
            'risk_level': risk_level,
            'triggered_rules': triggered_rules,
            'rule_count': len(triggered_rules),
            'recommendations': list(recommendations),
            'severity_breakdown': self._get_severity_breakdown(triggered_rules)
        }
        
        return result
    
    def _calculate_risk_level(self, score):
        for level, (min_score, max_score) in self.risk_thresholds.items():
            if min_score <= score <= max_score:
                return level
        
        return 'HIGH'
    
    def _get_severity_breakdown(self, triggered_rules):
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
        return [
            {
                'name': rule['name'],
                'risk_score': rule['risk_score'],
                'severity': rule['severity']
            }
            for rule in self.risk_rules
        ]


def print_analysis_report(analysis_result):
    print("\n" + "=" * 70)
    print("SECURITY ANALYSIS REPORT")
    print("=" * 70)
    print(f"\nRisk Score: {analysis_result['risk_score']}/100")
    print(f"Risk Level: {analysis_result['risk_level']}")
    print(f"\nSeverity Breakdown:")
    breakdown = analysis_result['severity_breakdown']
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = breakdown[severity]
        if count > 0:
            print(f"  {severity}: {count} rule(s)")
    
    print(f"\nTriggered Rules ({analysis_result['rule_count']}):")
    if analysis_result['triggered_rules']:
        for i, rule in enumerate(analysis_result['triggered_rules'], 1):
            print(f"\n  {i}. {rule['name']} ({rule['severity']})")
            print(f"     Score: +{rule['risk_score']}")
            print(f"     {rule['description']}")
            print(f"     → {rule['recommendation']}")
    else:
        print("  None - Site appears safe")
    
    if analysis_result['recommendations']:
        print(f"\nRecommendations:")
        for i, rec in enumerate(analysis_result['recommendations'], 1):
            print(f"  {i}. {rec}")
    
    print("\n" + "=" * 70)

if __name__ == "__main__":
    print("=" * 70)
    print("RULE-BASED ANALYZER - TEST MODE")
    print("=" * 70)
    
    analyzer = RuleBasedAnalyzer()
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
  
    print("\n\n[TEST 3] Analyzing Phishing Website")
    print("-" * 70)
    
    phishing_features = {
        'url_length': 65,
        'is_https': 0,  
        'has_ip_address': 1,  
        'has_suspicious_tld': 1,  
        'has_login_form': 1,  
        'entropy': 4.8,  
        'subdomain_count': 5,  
        'external_script_count': 15,  
        'has_urgency_words': 1,  
        'has_prize_words': 0,
        'has_favicon': 0,
        'sensitive_keyword_count': 4,  
        'has_hidden_elements': 1,
        'has_at_symbol': 1
    }
    
    result = analyzer.analyze(phishing_features)
    print_analysis_report(result)
    

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