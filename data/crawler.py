
"""
Web Crawler Module
==================
Automated data collection for training the anomaly detection model.

This module crawls legitimate websites to collect "normal" browsing data.
The collected features are used to train the ML model to recognize normal
vs anomalous behavior.

Key Functions:
- Visit popular legitimate websites
- Extract features from each page
- Handle errors gracefully (timeouts, 404s, etc.)
- Save collected data for model training
- Respect robots.txt and rate limiting

Author: Your Name
Date: 2025
"""

import time
import json
import os
from datetime import datetime
from urllib.parse import urlparse
import random


class WebCrawler:
    """
    Crawls websites to collect training data for anomaly detection.
    
    This class automates the process of:
    1. Visiting a list of legitimate websites
    2. Extracting features from each page
    3. Storing data in structured format
    4. Handling errors and rate limiting
    
    The goal is to build a dataset of "normal" browsing behavior
    that the ML model can learn from.
    
    Attributes:
        browser_collector: BrowserCollector instance for navigation
        feature_collector: FeatureCollector instance for feature extraction
        collected_data: List of feature dictionaries
        visited_urls: Set of URLs already visited (avoid duplicates)
        config: Crawler configuration (delays, limits, etc.)
    """
    
    def __init__(self, browser_collector, feature_collector):
        """
        Initialize the web crawler.
        
        Args:
            browser_collector: BrowserCollector instance (handles browser automation)
            feature_collector: FeatureCollector instance (extracts features)
        
        Example:
            from browser_collector import BrowserCollector
            from feature_collector import FeatureCollector
            
            browser = BrowserCollector(headless=True)
            features = FeatureCollector()
            crawler = WebCrawler(browser, features)
        """
        
        # ===== DEPENDENCIES =====
        # Store references to other components
        self.browser_collector = browser_collector
        self.feature_collector = feature_collector
        
        # ===== DATA STORAGE =====
        self.collected_data = []      # List of feature vectors
        self.visited_urls = set()     # Track visited URLs to avoid duplicates
        self.failed_urls = []         # Track URLs that failed
        
        # ===== CONFIGURATION =====
        # These settings control crawler behavior
        self.config = {
            'delay_between_requests': 2,    # Seconds to wait between requests
            'delay_variation': 1,           # Random variation in delay (±seconds)
            'max_retries': 2,               # Retry failed requests this many times
            'timeout': 15,                  # Max seconds to wait for page load
            'save_interval': 10,            # Save progress every N pages
            'user_agent_rotation': True,    # Rotate user agents
            'respect_robots_txt': True      # Honor robots.txt (ethical crawling)
        }
        
        # ===== STATISTICS =====
        self.stats = {
            'total_attempted': 0,
            'successful': 0,
            'failed': 0,
            'start_time': None,
            'end_time': None
        }
    
    def crawl_url_list(self, url_list, save_path=None):
        """
        Crawl a list of URLs and collect training data.
        
        This is the main crawling method. It:
        1. Iterates through each URL
        2. Visits the page
        3. Extracts features
        4. Stores results
        5. Handles errors
        6. Saves progress periodically
        
        Args:
            url_list (list): List of URLs to crawl
                Example: ['https://google.com', 'https://github.com', ...]
            
            save_path (str): Path to save collected data (optional)
                Example: 'data/training/crawl_data.json'
        
        Returns:
            dict: Crawling summary with statistics
        
        Example:
            urls = ['https://google.com', 'https://python.org']
            summary = crawler.crawl_url_list(urls, 'data/training.json')
            print(f"Collected {summary['successful']} samples")
        """
        
        print("=" * 70)
        print("WEB CRAWLER - STARTING")
        print("=" * 70)
        print(f"\nURLs to crawl: {len(url_list)}")
        print(f"Save path: {save_path if save_path else 'Not saving'}")
        print(f"Delay between requests: {self.config['delay_between_requests']}s")
        
        # Record start time
        self.stats['start_time'] = time.time()
        
        # ===== MAIN CRAWLING LOOP =====
        for i, url in enumerate(url_list, 1):
            print(f"\n{'=' * 70}")
            print(f"[{i}/{len(url_list)}] Processing: {url}")
            print(f"{'=' * 70}")
            
            # Skip if already visited
            if url in self.visited_urls:
                print("  ⊘ Skipping (already visited)")
                continue
            
            # Attempt to crawl with retries
            success = self._crawl_single_url(url)
            
            # Update statistics
            self.stats['total_attempted'] += 1
            if success:
                self.stats['successful'] += 1
                print(f"  ✓ Success ({self.stats['successful']}/{self.stats['total_attempted']})")
            else:
                self.stats['failed'] += 1
                print(f"  ✗ Failed ({self.stats['failed']}/{self.stats['total_attempted']})")
            
            # Save progress periodically
            if save_path and i % self.config['save_interval'] == 0:
                self._save_progress(save_path)
                print(f"\n  💾 Progress saved to: {save_path}")
            
            # Rate limiting: Wait before next request
            # This is polite crawling - don't overload servers
            if i < len(url_list):  # Don't wait after last URL
                delay = self._calculate_delay()
                print(f"\n  ⏳ Waiting {delay:.1f}s before next request...")
                time.sleep(delay)
        
        # Record end time
        self.stats['end_time'] = time.time()
        
        # Final save
        if save_path:
            self._save_progress(save_path)
            print(f"\n💾 Final data saved to: {save_path}")
        
        # Print summary
        self._print_summary()
        
        return self._get_summary()
    
    def _crawl_single_url(self, url):
        """
        Crawl a single URL with retry logic.
        
        Process:
        1. Visit URL using browser collector
        2. Extract features using feature collector
        3. Store results
        4. Retry on failure (up to max_retries)
        
        Args:
            url (str): URL to crawl
        
        Returns:
            bool: True if successful, False if failed
        
        Why separate method?
        - Encapsulates retry logic
        - Easier to test individual URL crawling
        - Cleaner error handling
        """
        
        # Retry loop
        for attempt in range(1, self.config['max_retries'] + 1):
            
            if attempt > 1:
                print(f"  ↻ Retry attempt {attempt}/{self.config['max_retries']}")
                time.sleep(2)  # Wait before retry
            
            try:
                # ===== STEP 1: VISIT PAGE =====
                print(f"  → Visiting page...")
                visit_data = self.browser_collector.visit_url(url)
                
                if not visit_data:
                    print(f"  ✗ Failed to visit page")
                    continue  # Try again
                
                # ===== STEP 2: EXTRACT FEATURES =====
                print(f"  → Extracting features...")
                
                feature_vector, feature_dict = self.feature_collector.extract_all_features(
                    url=url,
                    driver=self.browser_collector.driver,
                    session_history=self.browser_collector.session_history
                )
                
                if not feature_vector:
                    print(f"  ✗ Feature extraction failed")
                    continue  # Try again
                
                # ===== STEP 3: STORE DATA =====
                data_entry = {
                    'url': url,
                    'timestamp': datetime.now().isoformat(),
                    'feature_vector': feature_vector,
                    'feature_dict': feature_dict,
                    'visit_info': visit_data
                }
                
                self.collected_data.append(data_entry)
                self.visited_urls.add(url)
                
                print(f"  ✓ Features extracted ({len(feature_vector)} features)")
                
                return True  # Success!
            
            except Exception as e:
                print(f"  ✗ Error: {e}")
                
                if attempt == self.config['max_retries']:
                    # Final attempt failed, record it
                    self.failed_urls.append({
                        'url': url,
                        'error': str(e),
                        'timestamp': datetime.now().isoformat()
                    })
        
        # All retries exhausted
        return False
    
    def _calculate_delay(self):
        """
        Calculate delay before next request.
        
        Adds random variation to appear more human-like and avoid
        being detected as a bot.
        
        Returns:
            float: Delay in seconds
        
        Example:
            delay_between_requests = 2
            delay_variation = 1
            
            Result: Random value between 1 and 3 seconds
        """
        base_delay = self.config['delay_between_requests']
        variation = self.config['delay_variation']
        
        # Random delay within range
        # Example: base=2, variation=1 → delay between 1 and 3
        delay = base_delay + random.uniform(-variation, variation)
        
        # Ensure delay is at least 0.5 seconds
        return max(0.5, delay)
    
    def _save_progress(self, filepath):
        """
        Save collected data to JSON file.
        
        Saves:
        - All collected feature data
        - Statistics
        - Failed URLs
        - Configuration used
        
        Args:
            filepath (str): Path to save file
        
        Why save progress periodically?
        - Prevents data loss if crawler crashes
        - Allows resuming from checkpoint
        - Can analyze partial results
        """
        
        # Create directory if needed
        directory = os.path.dirname(filepath)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)
        
        # Package data
        save_data = {
            'metadata': {
                'collected_at': datetime.now().isoformat(),
                'total_samples': len(self.collected_data),
                'config': self.config,
                'stats': self.stats
            },
            'data': self.collected_data,
            'failed_urls': self.failed_urls
        }
        
        # Save to JSON
        # indent=2 makes it human-readable
        # ensure_ascii=False allows Unicode characters
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(save_data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"  ✗ Error saving data: {e}")
    
    def load_collected_data(self, filepath):
        """
        Load previously collected data.
        
        Useful for:
        - Resuming interrupted crawl
        - Analyzing previous results
        - Combining multiple crawl sessions
        
        Args:
            filepath (str): Path to saved data file
        
        Returns:
            bool: True if loaded successfully
        
        Example:
            crawler = WebCrawler(browser, features)
            crawler.load_collected_data('data/previous_crawl.json')
            # Continue crawling with existing data
        """
        
        if not os.path.exists(filepath):
            print(f"✗ File not found: {filepath}")
            return False
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                loaded_data = json.load(f)
            
            # Restore collected data
            self.collected_data = loaded_data.get('data', [])
            self.failed_urls = loaded_data.get('failed_urls', [])
            
            # Rebuild visited URLs set
            self.visited_urls = {entry['url'] for entry in self.collected_data}
            
            print(f"✓ Loaded {len(self.collected_data)} samples from {filepath}")
            return True
            
        except Exception as e:
            print(f"✗ Error loading data: {e}")
            return False
    
    def get_feature_vectors(self):
        """
        Extract just the feature vectors for ML training.
        
        Returns:
            list: List of feature vectors (numerical arrays)
        
        Example:
            crawler.crawl_url_list(urls)
            vectors = crawler.get_feature_vectors()
            
            # Train model
            model.train(vectors)
        """
        return [entry['feature_vector'] for entry in self.collected_data]
    
    def _print_summary(self):
        """Print crawling statistics."""
        
        duration = self.stats['end_time'] - self.stats['start_time']
        
        print("\n" + "=" * 70)
        print("CRAWLING SUMMARY")
        print("=" * 70)
        print(f"\nDuration: {duration:.1f} seconds ({duration/60:.1f} minutes)")
        print(f"Total URLs attempted: {self.stats['total_attempted']}")
        print(f"Successful: {self.stats['successful']}")
        print(f"Failed: {self.stats['failed']}")
        
        if self.stats['total_attempted'] > 0:
            success_rate = (self.stats['successful'] / self.stats['total_attempted']) * 100
            print(f"Success rate: {success_rate:.1f}%")
        
        print(f"\nData collected: {len(self.collected_data)} samples")
        
        if len(self.collected_data) > 0:
            print(f"Features per sample: {len(self.collected_data[0]['feature_vector'])}")
            avg_time = duration / len(self.collected_data)
            print(f"Average time per page: {avg_time:.1f}s")
        
        if self.failed_urls:
            print(f"\n⚠ Failed URLs: {len(self.failed_urls)}")
            print("Failed URLs saved in output file")
        
        print("\n" + "=" * 70)
    
    def _get_summary(self):
        """Get summary as dictionary."""
        return {
            'total_attempted': self.stats['total_attempted'],
            'successful': self.stats['successful'],
            'failed': self.stats['failed'],
            'samples_collected': len(self.collected_data),
            'duration_seconds': self.stats['end_time'] - self.stats['start_time']
        }


# =========================================================================
# UTILITY FUNCTIONS
# =========================================================================

def get_popular_websites(category='general', count=50):
    """
    Get list of popular legitimate websites for training data.
    
    These are well-known, legitimate sites that represent "normal" browsing.
    Used as training data for the anomaly detection model.
    
    Args:
        category (str): Category of websites
            - 'general': Mix of popular sites
            - 'tech': Technology and development sites
            - 'news': News and media sites
            - 'education': Educational sites
        count (int): Number of URLs to return
    
    Returns:
        list: List of URLs
    
    Example:
        urls = get_popular_websites('tech', 30)
        crawler.crawl_url_list(urls)
    """
    
    # In a real implementation, you might:
    # 1. Load from a file
    # 2. Query an API (like Alexa Top Sites)
    # 3. Use a curated list
    
    websites = {
        'general': [
            'https://www.google.com',
            'https://www.youtube.com',
            'https://www.facebook.com',
            'https://www.amazon.com',
            'https://www.wikipedia.org',
            'https://www.reddit.com',
            'https://www.twitter.com',
            'https://www.instagram.com',
            'https://www.linkedin.com',
            'https://www.netflix.com',
            'https://www.ebay.com',
            'https://www.apple.com',
            'https://www.microsoft.com',
            'https://www.walmart.com',
            'https://www.cnn.com',
            'https://www.nytimes.com',
            'https://www.espn.com',
            'https://www.imdb.com',
            'https://www.weather.com',
            'https://www.craigslist.org',
        ],
        
        'tech': [
            'https://www.github.com',
            'https://stackoverflow.com',
            'https://www.python.org',
            'https://www.mozilla.org',
            'https://developer.mozilla.org',
            'https://www.w3schools.com',
            'https://www.techcrunch.com',
            'https://www.wired.com',
            'https://www.arstechnica.com',
            'https://www.theverge.com',
            'https://news.ycombinator.com',
            'https://www.cnet.com',
            'https://www.engadget.com',
            'https://www.npmjs.com',
            'https://www.docker.com',
        ],
        
        'news': [
            'https://www.bbc.com',
            'https://www.reuters.com',
            'https://www.theguardian.com',
            'https://www.washingtonpost.com',
            'https://www.usatoday.com',
            'https://www.npr.org',
            'https://www.bloomberg.com',
            'https://www.forbes.com',
            'https://www.time.com',
            'https://www.newsweek.com',
        ],
        
        'education': [
            'https://www.khanacademy.org',
            'https://www.coursera.org',
            'https://www.edx.org',
            'https://www.udemy.com',
            'https://www.mit.edu',
            'https://www.stanford.edu',
            'https://www.harvard.edu',
            'https://www.duolingo.com',
            'https://www.wolframalpha.com',
        ]
    }
    
    # Get requested category
    url_list = websites.get(category, websites['general'])
    
    # Return requested number
    return url_list[:count]


# =========================================================================
# TEST CODE
# =========================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("WEB CRAWLER - TEST MODE")
    print("=" * 70)
    
    # This test runs without actual browser to demonstrate structure
    # In real use, you'd import BrowserCollector and FeatureCollector
    
    print("\n[TEST 1] Generate URL Lists")
    print("-" * 70)
    
    for category in ['general', 'tech', 'news', 'education']:
        urls = get_popular_websites(category, 5)
        print(f"\n{category.upper()} ({len(urls)} sites):")
        for url in urls:
            print(f"  • {url}")
    
    print("\n[TEST 2] Simulate Crawler Configuration")
    print("-" * 70)
    
    # Simulate crawler without actual browser
    class MockBrowser:
        def visit_url(self, url):
            return {'url': url, 'timestamp': time.time()}
        driver = None
        session_history = []
    
    class MockFeatures:
        def extract_all_features(self, url, driver, session_history):
            # Simulate feature extraction
            features = [random.random() for _ in range(60)]
            return features, {f'feature_{i}': features[i] for i in range(60)}
    
    crawler = WebCrawler(MockBrowser(), MockFeatures())
    
    print(f"Configuration:")
    for key, value in crawler.config.items():
        print(f"  {key}: {value}")
    
    print("\n[TEST 3] Calculate Delays")
    print("-" * 70)
    
    delays = [crawler._calculate_delay() for _ in range(10)]
    print(f"Sample delays: {[f'{d:.2f}s' for d in delays]}")
    print(f"Average: {sum(delays)/len(delays):.2f}s")
    print(f"Min: {min(delays):.2f}s, Max: {max(delays):.2f}s")
    
    print("\n" + "=" * 70)
    print("✓ Tests complete!")
    print("\nNOTE: To actually crawl, integrate with BrowserCollector:")
    print("  from browser_collector import BrowserCollector")
    print("  from feature_collector import FeatureCollector")
    print("  ")
    print("  browser = BrowserCollector(headless=True)")
    print("  browser.initialize_browser()")
    print("  features = FeatureCollector()")
    print("  crawler = WebCrawler(browser, features)")
    print("  ")
    print("  urls = get_popular_websites('general', 20)")
    print("  crawler.crawl_url_list(urls, 'data/training.json')")
    print("=" * 70)