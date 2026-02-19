"""
Browser Collector Module - Minimal Working Version
"""

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
import time
from datetime import datetime


class BrowserCollector:
    """Manages browser automation for data collection."""
    
    def __init__(self, headless=True):
        self.driver = None
        self.headless = headless
        self.session_history = []
        
    def initialize_browser(self):
        """Set up Chrome browser with Selenium."""
        print("Initializing Chrome browser...")
        
        chrome_options = Options()
        
        if self.headless:
            chrome_options.add_argument('--headless')
        
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-gpu')
        chrome_options.add_argument('--disable-blink-features=AutomationControlled')
        chrome_options.add_argument('--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        chrome_options.add_experimental_option('excludeSwitches', ['enable-logging'])
        
        try:
            service = Service(ChromeDriverManager().install())
            self.driver = webdriver.Chrome(service=service, options=chrome_options)
            self.driver.set_page_load_timeout(15)
            self.driver.implicitly_wait(5)
            print("✓ Browser initialized successfully")
            return True
        except Exception as e:
            print(f"✗ Error initializing browser: {e}")
            return False
    
    def visit_url(self, url):
        """Visit a URL and return page data."""
        if not self.driver:
            print("Error: Browser not initialized")
            return None
        
        print(f"Visiting: {url}")
        
        try:
            start_time = time.time()
            self.driver.get(url)
            
            WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            time.sleep(2)
            end_time = time.time()
            load_time = end_time - start_time
            
            page_data = {
                'url': url,
                'final_url': self.driver.current_url,
                'title': self.driver.title,
                'load_time': round(load_time, 2),
                'timestamp': start_time,
                'datetime': datetime.fromtimestamp(start_time).strftime('%Y-%m-%d %H:%M:%S')
            }
            
            self.session_history.append(page_data)
            print(f"✓ Page loaded in {load_time:.2f}s")
            return page_data
            
        except TimeoutException:
            print(f"✗ Timeout loading: {url}")
            return None
        except Exception as e:
            print(f"✗ Error: {e}")
            return None
    
    def get_session_summary(self):
        """Get session summary statistics."""
        if not self.session_history:
            return {
                'pages_visited': 0,
                'total_time': 0,
                'avg_load_time': 0,
                'first_visit': None,
                'last_visit': None
            }
        
        total_load_time = sum(page['load_time'] for page in self.session_history)
        
        return {
            'pages_visited': len(self.session_history),
            'total_time': round(total_load_time, 2),
            'avg_load_time': round(total_load_time / len(self.session_history), 2),
            'first_visit': self.session_history[0]['datetime'],
            'last_visit': self.session_history[-1]['datetime']
        }
    
    def close_browser(self):
        """Close the browser."""
        if self.driver:
            self.driver.quit()
            print("✓ Browser closed")


# ===== TEST CODE =====
if __name__ == "__main__":
    print("=" * 70)
    print("BROWSER COLLECTOR - TEST MODE")
    print("=" * 70)
    
    # Step 1: Create collector
    print("\n[1] Creating BrowserCollector...")
    collector = BrowserCollector(headless=False)
    
    # Step 2: Initialize browser
    print("\n[2] Initializing browser...")
    if not collector.initialize_browser():
        print("✗ Setup failed")
        exit(1)
    
    # Step 3: Test URLs
    test_urls = [
        'https://www.google.com',
        'https://www.github.com',
        'https://www.python.org'
    ]
    
    print(f"\n[3] Testing with {len(test_urls)} URLs...")
    print("-" * 70)
    
    successful = 0
    for i, url in enumerate(test_urls, 1):
        print(f"\nTest {i}/{len(test_urls)}")
        result = collector.visit_url(url)
        if result:
            successful += 1
        time.sleep(2)
    
    # Step 4: Display summary
    print("\n" + "=" * 70)
    print("SESSION SUMMARY")
    print("=" * 70)
    
    summary = collector.get_session_summary()
    print(f"Pages visited: {summary['pages_visited']}")
    print(f"Successful: {successful}")
    print(f"Failed: {len(test_urls) - successful}")
    print(f"Total time: {summary['total_time']:.2f}s")
    print(f"Average time: {summary['avg_load_time']:.2f}s")
    
    if summary['first_visit']:
        print(f"First visit: {summary['first_visit']}")
        print(f"Last visit: {summary['last_visit']}")
    
    # Step 5: Cleanup
    print("\n[4] Closing browser...")
    collector.close_browser()
    
    print("\n✓ Test complete!")
    print("=" * 70)