"""
Web Crawler Module
==================
Automated data collection for training the anomaly detection model.
"""

import sys
import os
import time
import json
from datetime import datetime
from urllib.parse import urlparse
import random

# ===== FIX IMPORTS =====
# Get current directory and project root
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)

# Add src directory to Python path
sys.path.insert(0, os.path.join(project_root, 'src'))

# Import after fixing path
try:
    from browser_collector import BrowserCollector
    from feature_processor import FeatureCollector
except ImportError as e:
    print(f"Import Error: {e}")
    print(f"\nCurrent dir: {current_dir}")
    print(f"Project root: {project_root}")
    print(f"Looking for files in: {os.path.join(project_root, 'src')}")
    sys.exit(1)


class WebCrawler:
    """Crawls websites to collect training data for anomaly detection."""
    
    def __init__(self, browser_collector, feature_collector):
        """
        Initialize the web crawler.
        
        Args:
            browser_collector: BrowserCollector instance
            feature_collector: FeatureCollector instance
        """
        self.browser_collector = browser_collector
        self.feature_collector = feature_collector
        
        self.collected_data = []
        self.visited_urls = set()
        self.failed_urls = []
        
        self.config = {
            'delay_between_requests': 2,
            'delay_variation': 1,
            'max_retries': 2,
            'timeout': 15,
            'save_interval': 10,
            'max_urls_per_session': 100
        }
        
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
        
        Args:
            url_list (list): List of URLs to crawl
            save_path (str): Path to save collected data
        
        Returns:
            dict: Crawling summary with statistics
        """
        print("=" * 70)
        print("WEB CRAWLER - STARTING")
        print("=" * 70)
        print(f"\nURLs to crawl: {len(url_list)}")
        print(f"Save path: {save_path if save_path else 'Not saving'}")
        print(f"Delay between requests: {self.config['delay_between_requests']}s")
        
        self.stats['start_time'] = time.time()
        
        for i, url in enumerate(url_list, 1):
            print(f"\n{'=' * 70}")
            print(f"[{i}/{len(url_list)}] Processing: {url}")
            print(f"{'=' * 70}")
            
            if url in self.visited_urls:
                print("  ⊘ Skipping (already visited)")
                continue
            
            success = self._crawl_single_url(url)
            
            self.stats['total_attempted'] += 1
            if success:
                self.stats['successful'] += 1
                print(f"  ✓ Success ({self.stats['successful']}/{self.stats['total_attempted']})")
            else:
                self.stats['failed'] += 1
                print(f"  ✗ Failed ({self.stats['failed']}/{self.stats['total_attempted']})")
            
            if save_path and i % self.config['save_interval'] == 0:
                self._save_progress(save_path)
                print(f"\n  💾 Progress saved to: {save_path}")
            
            if i < len(url_list):
                delay = self._calculate_delay()
                print(f"\n  ⏳ Waiting {delay:.1f}s before next request...")
                time.sleep(delay)
        
        self.stats['end_time'] = time.time()
        
        if save_path:
            self._save_progress(save_path)
            print(f"\n💾 Final data saved to: {save_path}")
        
        self._print_summary()
        
        return self._get_summary()
    
    def _crawl_single_url(self, url):
        """Crawl a single URL with retry logic."""
        for attempt in range(1, self.config['max_retries'] + 1):
            
            if attempt > 1:
                print(f"  ↻ Retry attempt {attempt}/{self.config['max_retries']}")
                time.sleep(2)
            
            try:
                print(f"  → Visiting page...")
                visit_data = self.browser_collector.visit_url(url)
                
                if not visit_data:
                    print(f"  ✗ Failed to visit page")
                    continue
                
                print(f"  → Extracting features...")
                
                feature_vector, feature_dict = self.feature_collector.extract_all_features(
                    url=url,
                    driver=self.browser_collector.driver,
                    session_history=self.browser_collector.session_history
                )
                
                if not feature_vector:
                    print(f"  ✗ Feature extraction failed")
                    continue
                
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
                
                return True
            
            except Exception as e:
                print(f"  ✗ Error: {e}")
                
                if attempt == self.config['max_retries']:
                    self.failed_urls.append({
                        'url': url,
                        'error': str(e),
                        'timestamp': datetime.now().isoformat()
                    })
        
        return False
    
    def _calculate_delay(self):
        """Calculate delay before next request."""
        base_delay = self.config['delay_between_requests']
        variation = self.config['delay_variation']
        delay = base_delay + random.uniform(-variation, variation)
        return max(0.5, delay)
    
    def _save_progress(self, filepath):
        """Save collected data to JSON file."""
        directory = os.path.dirname(filepath)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)
        
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
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(save_data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"  ✗ Error saving data: {e}")
    
    def get_feature_vectors(self):
        """Extract just the feature vectors for ML training."""
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


def get_popular_websites(category='general', count=50):
    """
    Get list of popular legitimate websites for training data.
    
    Args:
        category (str): Category of websites
        count (int): Number of URLs to return
    
    Returns:
        list: List of URLs
    """
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
    
    url_list = websites.get(category, websites['general'])
    return url_list[:count]


# ===== TEST CODE =====
if __name__ == "__main__":
    print("=" * 70)
    print("WEB CRAWLER - TEST MODE")
    print("=" * 70)
    
    print("\n[TEST 1] Generate URL Lists")
    print("-" * 70)
    
    for category in ['general', 'tech', 'news', 'education']:
        urls = get_popular_websites(category, 5)
        print(f"\n{category.upper()} ({len(urls)} sites):")
        for url in urls:
            print(f"  • {url}")
    
    print("\n[TEST 2] Simulate Crawler Configuration")
    print("-" * 70)
    
    # Mock objects for testing without actual browser
    class MockBrowser:
        def visit_url(self, url):
            return {'url': url, 'timestamp': time.time(), 'title': 'Test', 'load_time': 1.0}
        driver = None
        session_history = []
    
    class MockFeatures:
        def extract_all_features(self, url, driver, session_history):
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
    print("\nNOTE: To actually crawl, run driver.py:")
    print("  python data/driver.py --samples 10 --visible")
    print("=" * 70) 