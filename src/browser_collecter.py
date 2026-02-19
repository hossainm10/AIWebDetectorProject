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
    def __init__(self, headless=True):
        self.driver=None
        self.headless=None
        self.session_history=[]

    def initialize_browser(self):
        print("Initializing Chrome Browser")

        chrome_options=Options()
        
        if self.headless:
            chrome_options.add_argument("--headless")
            print(" Running in headless mode(no Gui)")
        
        chrome_options.add_argument("--no sandbox")

        chrome_options.add_argument("--disable-dev-shm-usage")

        chrome_options.add_argument("--disable-gpu")

        chrome_options.add_argument("--disable-blink-features=AutomationControlled")

        chrome_options.add_argument("'--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64)'" \
        "AppleWebKit/537.36 (KHTML, like Gecko)" \
        "Chrome/120.0.0.0 Safari/537.36")

        chrome_options.add_experimental_option("excludeSwitches",['enable-logging'])

        try:
            print(" Downloading/locating Chromedriver")
            service= Service(ChromeDriverManager().install())

            print(" Starting Chrome browser...  ")
            self.driver=webdriver.Chrome(service=service,options=chrome_options)


            self.driver.set_page_load_timeout(15)

            self.driver.implicitly_wait(5)

            print("Success! Browser initialized successfully")

            return True
        except Exception as e:
            print(f"Error Initialzing browser: {e}")
            print("Troubleshooting Tips: ")
            print(" 1.Make sure Chrome Browser is installed")
            print(" 2.Check your internet connection(ChromeDriver needs to be downloaded)")
            print(" 3.Try running as administrator(Windows) or sudo(Linux)")
            return False
    

    def visit_url(self, url):
        if not self.driver:
            print("Error: Browser not intialized. Call initialized_browser() first.")
            return None
        print(f"Visiting : {url}")

        try:
            start_time=time.time()

            self.driver.get(url)

            try:
                WebDriverWait(self.driver,10).until(EC.presence_of_all_elements_located((By.TAG_NAME,"Body")))
            except TimeoutException:
                print(" Warning: Body element took to long to load!")

            time.sleep(2)

            end_time=time.time()
            load_time=end_time-start_time
            page_data={
                'url':url,
                'final_url': self.driver.current_url,
                'title':self.driver.title, 
                'load_time': round(load_time,2),
                'timestamp': start_time,
                'datetime':datetime.fromtimestamp(start_time).strftime("%Y-%m-%d %H-%M-%S")
            
            }

            self.session_history.append(page_data)

            print(f"Page Loaded in {load_time:.2f}s")
            print(f"Title: {page_data['title']}")
            
            if url!=page_data['final_url']:
                print(f"    Redirected to: {page_data['final_url']}")
            return page_data
        
        except TimeoutException:
            print(f"    Timeout Loading: {url}")
            print("     Page took too long to respond")
            return None
        
        except WebDriverException as e:
            print(f"WebDriver error: {e}")
            return None
        
        except Exception as e:
            print(f"Unexpected error: {e}")
            return None
    def get_page_source(self):
        if self.driver:
            return self.driver.page_source
        return None
    def get_current_url(self):
        if self.driver:
            return self.driver.current_url
        return None
    
    def take_screenshot(self,filepath):
        if not self.driver:
            print("Error: Browser not initialized")
            return False
        try:
            self.driver.save_screenshot(filepath)
            print(f"Screenshot saved to: {filepath}")
            return True
        except Exception as e:
            print(f"Error in screenshotting: {e}")
            return False
        
    def execute_js(self,script):
        if self.driver:
            return self.driver.execute_script(script)
        return None
    def get_session_summary(self):
        if not self.session_history:
            return {
                "pages visited": 0,
                "total_time":0,
                "avg_load_time":0

            }
        total_load_time= sum(page['load_time'] for page in self.session_history)

        return {
                "pages visited": len(self.session_history),
                "total_time":round(total_load_time,2),
                "avg_load_time":round(total_load_time)/len(self.session_history,2),
                'first_visit': self.session_history[0]['datetime'],
                'last_visit': self.session_history[-1]['datetime']
            }
    
    def close_browser(self):
        if self.driver:
            try:
                self.driver.quit()
                print("Browser Closed!")
                return True
            except Exception as e:
                print(f"Warning: Error closing browser:{e}")

            finally:
                self.driver=None

if __name__ == "__main__":
    print("=" * 60)
    print("BROWSER COLLECTOR - TEST MODE")
    print("=" * 60)
    
    # Create collector instance with visible browser (for testing)
    print("\n[1] Creating BrowserCollector...")
    collector = BrowserCollector(headless=False)  # Set to True to hide browser
    
    # Initialize browser
    print("\n[2] Initializing browser...")
    if not collector.initialize_browser():
        print("\n✗ Setup failed. Cannot continue.")
        exit(1)
    
    # Test URLs to visit
    test_urls = [
        'https://www.google.com',
        'https://www.github.com',
        'https://www.python.org',
        'https://www.wikipedia.org'
    ]
    
    print(f"\n[3] Testing with {len(test_urls)} URLs...")
    print("-" * 60)
    
    # Visit each URL
    successful_visits = 0
    for i, url in enumerate(test_urls, 1):
        print(f"\nTest {i}/{len(test_urls)}")
        result = collector.visit_url(url)
        
        if result:
            successful_visits += 1
            # Optional: take screenshot
            # collector.take_screenshot(f'screenshots/test_{i}.png')
        
        # Pause between requests (be nice to servers)
        if i < len(test_urls):
            time.sleep(2)
    
    # Display session summary
    print("\n" + "=" * 60)
    print("SESSION SUMMARY")
    print("=" * 60)
    
    summary = collector.get_session_summary()
    print(f"Pages visited: {summary['pages_visited']}")
    print(f"Successful: {successful_visits}")
    print(f"Failed: {len(test_urls) - successful_visits}")
    print(f"Total load time: {summary['total_time']:.2f}s")
    print(f"Average load time: {summary['avg_load_time']:.2f}s")
    print(f"First visit: {summary['first_visit']}")
    print(f"Last visit: {summary['last_visit']}")
    
    # Display visit history
    print("\n" + "=" * 60)
    print("VISIT HISTORY")
    print("=" * 60)
    for i, page in enumerate(collector.session_history, 1):
        print(f"\n{i}. {page['url']}")
        print(f"   Title: {page['title']}")
        print(f"   Load time: {page['load_time']}s")
        print(f"   Time: {page['datetime']}")
    
    # Close browser
    print("\n" + "=" * 60)
    print("[4] Closing browser...")
    collector.close_browser()
    
    print("\n✓ Test complete!")
    print("=" * 60)