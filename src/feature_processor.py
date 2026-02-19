from urllib.parse import urlparse, parse_qs
import re
import math
from collections import Counter
from selenium.webdriver.common.by import By
from selenium.common.exceptions import NoSuchElementException



class FeatureCollector:

    def __init__(self):
        self.suspicious_tlds=[
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".gq",
        ".xyz",
        ".top",
        ".work",
        ".club",
        ".online"]

        self.url_shorteners=[
            "bit.ly",
            "tinyurl.com",
            "goo.gl",
            "t.co",
            "ow.ly",
            "buff.ly",
            "is.gd",
            "cli.gs",
            "short.io",
            "rebrand.ly"
        ]

        self.sensitive_keywords=[
        "login", "credit","password","signin","sign-in","card","ssn","social","bank","account",
        "routing","verify","confirm","validation","secure","security","protected","Update","suspended","locked",
        "urgent","immediate", "expire"
        ]


    def extract_url_features(self,url):
        features={}

        try:
            parsed= urlparse(url)

            scheme=parsed.scheme
            domain=parsed.netloc
            query=parsed.query
            path=parsed.path

        except Exception as e:
            print(f"Counldn't parse Url: {url} with error {e}")
            return self._get_default_url_features()
        
        features['url_length']=len(url)

        features['domain_length'] = len(domain)
       
        
        features['path_length'] = len(path)
      
        
        features['query_length'] = len(query)
      
        if domain:
            features['subdomain_count'] = max(0, domain.count('.') - 1)
        else:
            features['subdomain_count'] = 0
        
       
        features['path_depth'] = path.count('/')
     
        features['query_param_count'] = len(parse_qs(query))
       
       
        features['has_ip_address'] = 1 if self._is_ip_address(domain) else 0
     
        features['has_suspicious_tld'] = 1 if any(url.endswith(tld) for tld in self.suspicious_tlds) else 0
        
        features['is_url_shortener'] = 1 if any(shortener in domain for shortener in self.url_shorteners) else 0
        
        features['has_at_symbol'] = 1 if '@' in url else 0
     
        features['double_slash_in_path'] = 1 if '//' in path else 0
       
        features['has_dash_in_domain'] = 1 if '-' in domain else 0
        
       
        # ========== CHARACTER ANALYSIS ==========
      
        digit_count = sum(c.isdigit() for c in url)
       
        normal_url_chars = ['/', '.', ':', '-', '_', '?', '=', '&', '#']
        special_chars = sum(1 for c in url if not c.isalnum() and c not in normal_url_chars)
        features['special_char_count'] = special_chars
    
        features['dash_count'] = url.count('-')
    
        
        features['underscore_count'] = url.count('_')
       
        
        features['dot_count'] = url.count('.')
       
        features['is_https'] = 1 if scheme == 'https' else 0
       
        features['has_port'] = 1 if parsed.port else 0
      
      
        features['entropy'] = self._calculate_entropy(url)
     
        features['has_punycode'] = 1 if 'xn--' in domain else 0
      
        # Check if domain has numbers (sometimes suspicious)
        features['domain_has_numbers'] = 1 if any(c.isdigit() for c in domain) else 0
       
        return features
    

    
    def extract_dom_features(self, driver):
    
        features = {}
        
        try:
           
            forms = driver.find_elements(By.TAG_NAME, 'form')
            features['form_count'] = len(forms)
            
            inputs = driver.find_elements(By.TAG_NAME, 'input')
            features['input_count'] = len(inputs)
            
            password_fields = driver.find_elements(By.CSS_SELECTOR, 'input[type="password"]')
            features['password_field_count'] = len(password_fields)
      
            has_login_form = len(password_fields) > 0 and len(inputs) >= 2
            features['has_login_form'] = 1 if has_login_form else 0
            
           
            email_fields = driver.find_elements(By.CSS_SELECTOR, 'input[type="email"]')
            features['email_input_count'] = len(email_fields)
            
       
            submit_buttons = driver.find_elements(By.CSS_SELECTOR, 'input[type="submit"], button[type="submit"]')
            features['submit_button_count'] = len(submit_buttons)
            
        
            scripts = driver.find_elements(By.TAG_NAME, 'script')
            features['script_count'] = len(scripts)
          
            current_domain = self._extract_domain(driver.current_url)
            external_scripts = 0
            
            for script in scripts:
                src = script.get_attribute('src')
                if src and current_domain not in src:
                    external_scripts += 1
            
            features['external_script_count'] = external_scripts
         
            features['external_script_ratio'] = external_scripts / len(scripts) if len(scripts) > 0 else 0
            
        
            
            iframes = driver.find_elements(By.TAG_NAME, 'iframe')
            features['iframe_count'] = len(iframes)
        
            
            links = driver.find_elements(By.TAG_NAME, 'a')
            features['link_count'] = len(links)
            
            external_links = 0
            for link in links:
                href = link.get_attribute('href')
                if href and current_domain not in href and href.startswith('http'):
                    external_links += 1
            
            features['external_link_count'] = external_links
            
        
            features['external_link_ratio'] = external_links / len(links) if len(links) > 0 else 0
          
            hidden_elements = driver.find_elements(By.CSS_SELECTOR, '[style*="display:none"], [style*="visibility:hidden"], [hidden]')
            features['hidden_element_count'] = len(hidden_elements)
            features['has_hidden_elements'] = 1 if len(hidden_elements) > 0 else 0
            
         
            popup_triggers = driver.find_elements(By.CSS_SELECTOR, '[onclick*="window.open"], [onclick*="alert"]')
            features['popup_trigger_count'] = len(popup_triggers)
            
           
            try:
                body = driver.find_element(By.TAG_NAME, 'body')
                oncontextmenu = body.get_attribute('oncontextmenu')
                features['disables_right_click'] = 1 if oncontextmenu and 'return false' in oncontextmenu else 0
            except:
                features['disables_right_click'] = 0
            
            
            try:
                favicon = driver.find_element(By.CSS_SELECTOR, 'link[rel*="icon"]')
                features['has_favicon'] = 1
            except NoSuchElementException:
                features['has_favicon'] = 0
            
            return features
            
        except Exception as e:
            
            print(f"Warning: Error extracting DOM features: {e}")
            return self._get_default_dom_features()
    
    def extract_content_features(self, driver):
        """
        Extract features from page content (visible text).
        
        This analyzes what the page says. Content features detect:
        - Phishing language patterns
        - Urgency words ("urgent", "expire")
        - Prize scams ("winner", "congratulations")
        - Requests for sensitive info
        
        Args:
            driver: Selenium WebDriver instance with page loaded
        
        Returns:
            dict: Dictionary with content-based features
        
        Example:
            features = collector.extract_content_features(browser.driver)
            print(features['has_urgency_words'])  # 1 (if "urgent" found)
        """
        features = {}
        
        try:
            # Get all visible text from page
            body = driver.find_element(By.TAG_NAME, 'body')
            page_text = body.text.lower()  # Convert to lowercase for matching
            
            # ========== TEXT STATISTICS ==========
            
            features['text_length'] = len(page_text)
            # Very short pages might be suspicious
            # Empty or nearly empty phishing pages
            
            words = page_text.split()
            features['word_count'] = len(words)
            
            # ========== KEYWORD ANALYSIS ==========
            
            # Count sensitive keywords
            sensitive_count = sum(1 for keyword in self.sensitive_keywords if keyword in page_text)
            features['sensitive_keyword_count'] = sensitive_count
            # High concentration of words like "password", "verify", "bank" is suspicious
            
            # Check for urgency language (scam tactic)
            urgency_words = ['urgent', 'immediate', 'immediately', 'verify', 'suspended', 
                           'expire', 'expires', 'expiring', 'act now', 'limited time']
            features['has_urgency_words'] = 1 if any(word in page_text for word in urgency_words) else 0
            
            # Count how many urgency words appear
            urgency_count = sum(1 for word in urgency_words if word in page_text)
            features['urgency_word_count'] = urgency_count
            
            # Check for prize/lottery scam language
            prize_words = ['winner', 'won', 'prize', 'congratulations', 'claim', 
                          'lottery', 'jackpot', 'selected', 'free money']
            features['has_prize_words'] = 1 if any(word in page_text for word in prize_words) else 0
            
            # Check for financial terms
            financial_words = ['credit card', 'bank account', 'routing number', 'ssn', 
                             'social security', 'tax', 'irs', 'refund']
            features['has_financial_terms'] = 1 if any(word in page_text for word in financial_words) else 0
            
            # ========== SPELLING & GRAMMAR ==========
            
            # Count obvious misspellings of common words (phishing indicator)
            # Phishers often make spelling errors
            misspellings = ['verificaton', 'secuirty', 'acount', 'pasword', 'confrim']
            features['has_misspellings'] = 1 if any(word in page_text for word in misspellings) else 0
            
            # Check for excessive punctuation (!!!, ???)
            features['has_excessive_punctuation'] = 1 if ('!!!' in page_text or '???' in page_text) else 0
            
            # ========== PHONE/EMAIL COLLECTION ==========
            
            # Count how many times user is asked for contact info
            phone_inputs = driver.find_elements(By.CSS_SELECTOR, 'input[type="tel"], input[name*="phone"]')
            features['phone_input_count'] = len(phone_inputs)
            
            # Already counted email inputs in DOM features, but check text too
            email_mentions = page_text.count('email') + page_text.count('e-mail')
            features['email_mention_count'] = min(email_mentions, 10)  # Cap at 10
            
            return features
            
        except Exception as e:
            print(f"Warning: Error extracting content features: {e}")
            return self._get_default_content_features()
    
    # ========================================================================
    # BEHAVIORAL FEATURE EXTRACTION (Session Patterns)
    # ========================================================================
    
    def extract_behavioral_features(self, session_history):
        """
        Extract features from browsing behavior over time.
        
        This analyzes patterns across multiple page visits:
        - How fast is the user navigating?
        - Are they jumping between many domains?
        - What's the sequence of actions?
        
        Args:
            session_history: List of visit dictionaries from BrowserCollector
        
        Returns:
            dict: Dictionary with behavioral features
        
        Example:
            # After visiting multiple pages
            features = collector.extract_behavioral_features(browser.session_history)
            print(features['domain_switching_rate'])  # 0.75 (high switching)
        """
        features = {}
        
        # Handle empty session
        if not session_history or len(session_history) == 0:
            return self._get_default_behavioral_features()
        
        # ========== SESSION METRICS ==========
        
        features['pages_visited'] = len(session_history)
        
        # Calculate session duration
        if len(session_history) > 1:
            first_visit = session_history[0]['timestamp']
            last_visit = session_history[-1]['timestamp']
            features['session_duration'] = last_visit - first_visit  # in seconds
        else:
            features['session_duration'] = 0
        
        # Average time per page
        total_load_time = sum(page.get('load_time', 0) for page in session_history)
        features['avg_time_per_page'] = total_load_time / len(session_history)
        
        # ========== NAVIGATION PATTERNS ==========
        
        # Extract domains from all visited URLs
        domains = [self._extract_domain(page.get('url', '')) for page in session_history]
        unique_domains = len(set(domains))
        
        features['unique_domain_count'] = unique_domains
        
        # Domain switching rate (high = suspicious, might be bot)
        features['domain_switching_rate'] = unique_domains / len(session_history)
        # Example: Visited 10 pages across 8 different domains = 0.8 (high switching)
        #          Visited 10 pages all on google.com = 0.1 (normal browsing)
        
        # ========== TIMING ANALYSIS ==========
        
        # Calculate time intervals between page visits
        if len(session_history) > 1:
            intervals = []
            for i in range(1, len(session_history)):
                interval = session_history[i]['timestamp'] - session_history[i-1]['timestamp']
                intervals.append(interval)
            
            features['avg_page_interval'] = sum(intervals) / len(intervals)
            features['min_page_interval'] = min(intervals)
            features['max_page_interval'] = max(intervals)
            
            # Very short intervals might indicate automated browsing (bot)
            features['has_rapid_navigation'] = 1 if min(intervals) < 1.0 else 0  # < 1 second
        else:
            features['avg_page_interval'] = 0
            features['min_page_interval'] = 0
            features['max_page_interval'] = 0
            features['has_rapid_navigation'] = 0
        
        # ========== URL PATTERN ANALYSIS ==========
        
        # Check if URLs follow sequential patterns (might be scraping/bot)
        # Example: page1.html, page2.html, page3.html
        urls = [page.get('url', '') for page in session_history]
        features['has_sequential_urls'] = 1 if self._detect_sequential_pattern(urls) else 0
        
        return features
    
    # ========================================================================
    # MASTER FEATURE COMBINATION
    # ========================================================================
    
    def extract_all_features(self, url, driver=None, session_history=None):
        """
        Extract ALL features from all sources.
        
        This is the master method that combines:
        - URL features (always available)
        - DOM features (requires loaded page)
        - Content features (requires loaded page)
        - Behavioral features (requires session history)
        
        Args:
            url (str): URL to analyze
            driver: Selenium WebDriver (optional, for DOM/content features)
            session_history: List of previous visits (optional, for behavioral features)
        
        Returns:
            tuple: (feature_vector, feature_dict)
                - feature_vector: List of numerical values for ML model
                - feature_dict: Dictionary with feature names for interpretation
        
        Example:
            collector = FeatureCollector()
            browser.visit_url('https://example.com')
            
            vector, features = collector.extract_all_features(
                'https://example.com',
                browser.driver,
                browser.session_history
            )
            
            # Use vector for ML model
            prediction = model.predict([vector])
            
            # Use features dict for rule-based analysis
            if features['has_login_form'] and not features['is_https']:
                print("DANGER: Insecure login form!")
        """
        # Start with URL features (always available)
        all_features = self.extract_url_features(url)
        
        # Add DOM features if driver provided
        if driver:
            dom_features = self.extract_dom_features(driver)
            all_features.update(dom_features)
            
            # Add content features (also requires driver)
            content_features = self.extract_content_features(driver)
            all_features.update(content_features)
        
        # Add behavioral features if session history provided
        if session_history:
            behavioral_features = self.extract_behavioral_features(session_history)
            all_features.update(behavioral_features)
        
        # Convert to numerical vector for ML
        feature_vector = list(all_features.values())
        
        return feature_vector, all_features
    
    # ========================================================================
    # HELPER METHODS
    # ========================================================================
    
    def _calculate_entropy(self, text):
        """
        Calculate Shannon entropy (randomness measure).
        
        Formula: H = -Σ p(x) * log₂(p(x))
        
        Where p(x) is the probability of character x appearing.
        
        Args:
            text (str): String to analyze
        
        Returns:
            float: Entropy value (0 = not random, higher = more random)
        
        Example:
            entropy('aaaaaaa')  # ~0 (very predictable)
            entropy('google')    # ~2.3 (normal word)
            entropy('x9k2m7p')  # ~2.8 (random-looking)
        """
        if not text or len(text) == 0:
            return 0.0
        
        # Count character frequencies
        # Example: "hello" -> {'h': 1, 'e': 1, 'l': 2, 'o': 1}
        counter = Counter(text)
        length = len(text)
        
        # Apply Shannon formula
        entropy = 0.0
        for count in counter.values():
            # Probability of this character
            probability = count / length
            
            # Add to entropy sum
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return round(entropy, 3)
    
    def _is_ip_address(self, domain):
        """
        Check if domain is an IPv4 address.
        
        Args:
            domain (str): Domain name to check
        
        Returns:
            bool: True if domain is IP address, False otherwise
        
        Example:
            _is_ip_address('192.168.1.1')  # True
            _is_ip_address('google.com')   # False
        """
        # Regex pattern for IPv4: xxx.xxx.xxx.xxx where xxx is 1-3 digits
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        
        if re.match(ip_pattern, domain):
            # Additional validation: each octet should be 0-255
            octets = domain.split('.')
            return all(0 <= int(octet) <= 255 for octet in octets)
        
        return False
    
    def _extract_domain(self, url):
        """
        Extract domain from URL.
        
        Args:
            url (str): Full URL
        
        Returns:
            str: Domain name only
        
        Example:
            _extract_domain('https://www.google.com/search')  # 'www.google.com'
        """
        try:
            parsed = urlparse(url)
            return parsed.netloc
        except:
            return ''
    
    def _detect_sequential_pattern(self, urls):
        """
        Detect if URLs follow sequential pattern (might indicate bot).
        
        Args:
            urls (list): List of URLs
        
        Returns:
            bool: True if sequential pattern detected
        
        Example:
            urls = ['page1.html', 'page2.html', 'page3.html']
            _detect_sequential_pattern(urls)  # True
        """
        if len(urls) < 3:
            return False
        
        # Look for incrementing numbers in URLs
        numbers_in_urls = []
        for url in urls:
            # Extract all numbers from URL
            numbers = re.findall(r'\d+', url)
            if numbers:
                numbers_in_urls.append(int(numbers[-1]))  # Use last number found
        
        # Check if numbers are sequential (1, 2, 3, 4...)
        if len(numbers_in_urls) >= 3:
            differences = [numbers_in_urls[i+1] - numbers_in_urls[i] for i in range(len(numbers_in_urls)-1)]
            # If all differences are 1, it's sequential
            return all(diff == 1 for diff in differences)
        
        return False
    
    # ========================================================================
    # DEFAULT FEATURE METHODS (For Error Handling)
    # ========================================================================
    
    def _get_default_url_features(self):
        """Return default URL features (all zeros) for malformed URLs."""
        return {
            'url_length': 0,
            'domain_length': 0,
            'path_length': 0,
            'query_length': 0,
            'subdomain_count': 0,
            'path_depth': 0,
            'query_param_count': 0,
            'has_ip_address': 0,
            'has_suspicious_tld': 0,
            'is_url_shortener': 0,
            'has_at_symbol': 0,
            'double_slash_in_path': 0,
            'has_dash_in_domain': 0,
            'digit_ratio': 0,
            'special_char_count': 0,
            'dash_count': 0,
            'underscore_count': 0,
            'dot_count': 0,
            'is_https': 0,
            'has_port': 0,
            'entropy': 0,
            'has_punycode': 0,
            'domain_has_numbers': 0
        }
    
    def _get_default_dom_features(self):
        """Return default DOM features (all zeros) for failed extraction."""
        return {
            'form_count': 0,
            'input_count': 0,
            'password_field_count': 0,
            'has_login_form': 0,
            'email_input_count': 0,
            'submit_button_count': 0,
            'script_count': 0,
            'external_script_count': 0,
            'external_script_ratio': 0,
            'iframe_count': 0,
            'link_count': 0,
            'external_link_count': 0,
            'external_link_ratio': 0,
            'hidden_element_count': 0,
            'has_hidden_elements': 0,
            'popup_trigger_count': 0,
            'disables_right_click': 0,
            'has_favicon': 0
        }
    
    def _get_default_content_features(self):
        """Return default content features (all zeros) for failed extraction."""
        return {
            'text_length': 0,
            'word_count': 0,
            'sensitive_keyword_count': 0,
            'has_urgency_words': 0,
            'urgency_word_count': 0,
            'has_prize_words': 0,
            'has_financial_terms': 0,
            'has_misspellings': 0,
            'has_excessive_punctuation': 0,
            'phone_input_count': 0,
            'email_mention_count': 0
        }
    
    def _get_default_behavioral_features(self):
        """Return default behavioral features (all zeros) for empty session."""
        return {
            'pages_visited': 0,
            'session_duration': 0,
            'avg_time_per_page': 0,
            'unique_domain_count': 0,
            'domain_switching_rate': 0,
            'avg_page_interval': 0,
            'min_page_interval': 0,
            'max_page_interval': 0,
            'has_rapid_navigation': 0,
            'has_sequential_urls': 0
        }


# ========================================================================
# TEST CODE
# ========================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("FEATURE COLLECTOR - TEST MODE")
    print("=" * 70)
    
    collector = FeatureCollector()
    
    # ===== TEST 1: URL FEATURES =====
    print("\n[TEST 1] URL Feature Extraction")
    print("-" * 70)
    
    test_urls = [
        ('https://www.google.com', 'Normal'),
        ('http://192.168.1.1/login', 'IP Address'),
        ('https://secure-banking-verify.xyz/update', 'Suspicious TLD'),
        ('https://bit.ly/3abc123', 'URL Shortener'),
        ('http://paypal@malicious.com/verify', '@ Symbol Trick'),
        ('https://x7k2m9p4b.com', 'High Entropy')
    ]
    
    for url, description in test_urls:
        print(f"\n{description}: {url}")
        features = collector.extract_url_features(url)
        
        # Print key features
        print(f"  Length: {features['url_length']}")
        print(f"  HTTPS: {'Yes' if features['is_https'] else 'No'}")
        print(f"  Entropy: {features['entropy']:.2f}")
        print(f"  Suspicious TLD: {'Yes' if features['has_suspicious_tld'] else 'No'}")
        print(f"  IP Address: {'Yes' if features['has_ip_address'] else 'No'}")
        print(f"  URL Shortener: {'Yes' if features['is_url_shortener'] else 'No'}")
        print(f"  Has @ Symbol: {'Yes' if features['has_at_symbol'] else 'No'}")
    
    # ===== TEST 2: ENTROPY CALCULATION =====
    print("\n\n[TEST 2] Entropy Analysis")
    print("-" * 70)
    
    test_strings = [
        ('aaaaaaa', 'Low - All same character'),
        ('google', 'Medium - Normal word'),
        ('x9k2m7p4b', 'High - Random string'),
        ('TheQuickBrownFox', 'Medium-High - Mixed case')
    ]
    
    for string, description in test_strings:
        entropy = collector._calculate_entropy(string)
        print(f"{description:30} '{string}' → Entropy: {entropy:.3f}")
    
    # ===== TEST 3: IP ADDRESS DETECTION =====
    print("\n\n[TEST 3] IP Address Detection")
    print("-" * 70)
    
    test_domains = [
        ('192.168.1.1', True),
        ('10.0.0.1', True),
        ('google.com', False),
        ('999.999.999.999', False),  # Invalid IP
        ('192.168.1', False)  # Incomplete IP
    ]
    
    for domain, expected in test_domains:
        result = collector._is_ip_address(domain)
        status = "✓" if result == expected else "✗"
        print(f"{status} {domain:20} → {result} (expected {expected})")
    
    # ===== TEST 4: SEQUENTIAL PATTERN DETECTION =====
    print("\n\n[TEST 4] Sequential URL Pattern Detection")
    print("-" * 70)
    
    url_sequences = [
        (['page1.html', 'page2.html', 'page3.html'], True, 'Sequential pages'),
        (['item1', 'item2', 'item3', 'item4'], True, 'Sequential items'),
        (['random1', 'random5', 'random2'], False, 'Non-sequential'),
        (['google.com', 'facebook.com'], False, 'Too few URLs')
    ]
    
    for urls, expected, description in url_sequences:
        result = collector._detect_sequential_pattern(urls)
        status = "✓" if result == expected else "✗"
        print(f"{status} {description:25} → {result} (expected {expected})")
    
    # ===== TEST 5: FEATURE COUNTS =====
    print("\n\n[TEST 5] Feature Count Summary")
    print("-" * 70)
    
    url_features = collector.extract_url_features('https://example.com')
    dom_features = collector._get_default_dom_features()
    content_features = collector._get_default_content_features()
    behavioral_features = collector._get_default_behavioral_features()
    
    print(f"URL Features: {len(url_features)}")
    print(f"DOM Features: {len(dom_features)}")
    print(f"Content Features: {len(content_features)}")
    print(f"Behavioral Features: {len(behavioral_features)}")
    print(f"\nTotal Features: {len(url_features) + len(dom_features) + len(content_features) + len(behavioral_features)}")
    
    print("\n" + "=" * 70)
    print("✓ All tests complete!")
    print("=" * 70)