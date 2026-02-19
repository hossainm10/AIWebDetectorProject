"""
Training Data Collection Driver
================================
Orchestrates the complete training data collection process.
"""

import sys
import os
import json
import argparse
from datetime import datetime


def setup_paths():
    """Add project directories to Python path."""
    # Get absolute path to this file
    current_file = os.path.abspath(__file__)
    current_dir = os.path.dirname(current_file)
    project_root = os.path.dirname(current_dir)
    
    # Add directories
    src_dir = os.path.join(project_root, 'src')
    utils_dir = os.path.join(project_root, 'utils')
    data_dir = os.path.join(project_root, 'data')
    
    # Add to path if not already there
    for directory in [src_dir, utils_dir, data_dir]:
        if directory not in sys.path:
            sys.path.insert(0, directory)
    
    return src_dir, utils_dir, data_dir

# Setup paths before importing
src_dir, utils_dir, data_dir = setup_paths()

# Debug: Print what we're doing
print(f"DEBUG: Adding to Python path:")
print(f"  src: {src_dir}")
print(f"  Exists: {os.path.exists(src_dir)}")
print(f"  browser_collector.py exists: {os.path.exists(os.path.join(src_dir, 'browser_collector.py'))}")

# Now try importing
try:
    import browser_collector
    import feature_processor  # Using  actual filename
    import crawler
    
    # Get the classes
    BrowserCollector = browser_collector.BrowserCollector
    FeatureCollector = feature_processor.FeatureCollector
    WebCrawler = crawler.WebCrawler
    get_popular_websites = crawler.get_popular_websites
    
    print("✓ All imports successful!")
    
except ImportError as e:
    print(f"\n✗ Import failed: {e}")
    print(f"\nPython is looking in these paths:")
    for path in sys.path[:5]:
        print(f"  {path}")
    print(f"\nFiles in src directory:")
    if os.path.exists(src_dir):
        for file in os.listdir(src_dir):
            if file.endswith('.py'):
                print(f"  {file}")
    sys.exit(1)




class TrainingDataDriver:
    """Orchestrates training  ===== FIX IMPORTS =====
# Get the directory where THIS file is located
current_dir = os.path.dirname(os.path.abspath(__file__))
# Go up one level to project root
project_root = os.path.dirname(current_dir)

# Add src, utils, anddata collection process."""
    
    def __init__(self, headless=True, output_dir='data/training'):
        print("=" * 70)
        print("TRAINING DATA COLLECTION - INITIALIZING")
        print("=" * 70)
        
        self.config = {
            'headless': headless,
            'output_dir': output_dir,
            'min_samples': 50,
            'target_samples': 100,
            'validate_features': True,
            'save_intermediate': True
        }
        
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            print(f"\n✓ Created output directory: {output_dir}")
        
        self.browser = None
        self.features = None
        self.crawler = None
        
        print(f"\nConfiguration:")
        for key, value in self.config.items():
            print(f"  {key}: {value}")
    
    def setup(self):
        """Set up all components."""
        print("\n" + "=" * 70)
        print("SETTING UP COMPONENTS")
        print("=" * 70)
        
        try:
            print("\n[1/3] Initializing browser...")
            self.browser = BrowserCollector(headless=self.config['headless'])
            
            if not self.browser.initialize_browser():
                print("✗ Browser initialization failed")
                return False
            
            print("✓ Browser ready")
            
            print("\n[2/3] Creating feature collector...")
            self.features = FeatureCollector()
            print("✓ Feature collector ready")
            
            print("\n[3/3] Setting up crawler...")
            self.crawler = WebCrawler(self.browser, self.features)
            
            self.crawler.config.update({
                'delay_between_requests': 3,
                'delay_variation': 1,
                'max_retries': 2,
                'save_interval': 10
            })
            
            print("✓ Crawler configured")
            print(f"  Delay: {self.crawler.config['delay_between_requests']}s")
            print(f"  Max retries: {self.crawler.config['max_retries']}")
            
            print("\n✓ All components ready!")
            return True
            
        except Exception as e:
            print(f"\n✗ Setup failed: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def collect_training_data(self, categories=None, samples_per_category=None):
        """Collect training data from multiple website categories."""
        
        if categories is None:
            categories = ['general', 'tech', 'news', 'education']
        
        if samples_per_category is None:
            samples_per_category = self.config['target_samples'] // len(categories)
        
        print("\n" + "=" * 70)
        print("COLLECTING TRAINING DATA")
        print("=" * 70)
        print(f"\nCategories: {', '.join(categories)}")
        print(f"Samples per category: {samples_per_category}")
        print(f"Total target: {len(categories) * samples_per_category}")
        
        print("\n" + "-" * 70)
        print("Generating URL lists...")
        print("-" * 70)
        
        all_urls = []
        for category in categories:
            urls = get_popular_websites(category, samples_per_category)
            all_urls.extend(urls)
            print(f"  {category:12} → {len(urls)} URLs")
        
        print(f"\nTotal URLs: {len(all_urls)}")
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = os.path.join(self.output_dir, f'training_data_{timestamp}.json')
        
        print(f"\nStarting crawl...")
        print(f"Output: {output_file}")
        
        summary = self.crawler.crawl_url_list(all_urls, output_file)
        
        samples_collected = len(self.crawler.collected_data)
        
        if samples_collected < self.config['min_samples']:
            print(f"\n⚠ WARNING: Only {samples_collected} samples collected")
            print(f"  Minimum needed: {self.config['min_samples']}")
        else:
            print(f"\n✓ Collected {samples_collected} samples")
        
        vectors_file = os.path.join(self.output_dir, f'feature_vectors_{timestamp}.json')
        self._export_feature_vectors(vectors_file)
        
        results = {
            'timestamp': timestamp,
            'categories': categories,
            'samples_per_category': samples_per_category,
            'total_urls': len(all_urls),
            'samples_collected': samples_collected,
            'crawl_summary': summary,
            'output_files': {
                'full_data': output_file,
                'feature_vectors': vectors_file
            }
        }
        
        summary_file = os.path.join(self.output_dir, f'collection_summary_{timestamp}.json')
        with open(summary_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n💾 Collection summary saved: {summary_file}")
        
        return results
    
    def _export_feature_vectors(self, filepath):
        """Export feature vectors for model training."""
        vectors = self.crawler.get_feature_vectors()
        
        export_data = {
            'metadata': {
                'n_samples': len(vectors),
                'n_features': len(vectors[0]) if vectors else 0,
                'collected_at': datetime.now().isoformat()
            },
            'feature_vectors': vectors
        }
        
        with open(filepath, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        print(f"💾 Feature vectors exported: {filepath}")
    
    def cleanup(self):
        """Clean up resources."""
        print("\n" + "=" * 70)
        print("CLEANING UP")
        print("=" * 70)
        
        if self.browser:
            self.browser.close_browser()
        
        print("✓ Cleanup complete")


def main():
    """Main function for command-line usage."""
    
    parser = argparse.ArgumentParser(
        description='Collect training data for browser anomaly detection'
    )
    
    parser.add_argument(
        '--categories',
        nargs='+',
        default=['general', 'tech', 'news', 'education'],
        help='Website categories to crawl'
    )
    
    parser.add_argument(
        '--samples',
        type=int,
        default=25,
        help='Number of samples per category (default: 25)'
    )
    
    parser.add_argument(
        '--headless',
        action='store_true',
        default=True,
        help='Run browser in headless mode (default: True)'
    )
    
    parser.add_argument(
        '--visible',
        action='store_true',
        help='Run browser in visible mode'
    )
    
    parser.add_argument(
        '--output',
        default='data/training',
        help='Output directory (default: data/training)'
    )
    
    args = parser.parse_args()
    
    headless = not args.visible if args.visible else args.headless
    
    driver = TrainingDataDriver(
        headless=headless,
        output_dir=args.output
    )
    
    try:
        if not driver.setup():
            print("\n✗ Setup failed. Exiting.")
            return 1
        
        results = driver.collect_training_data(
            categories=args.categories,
            samples_per_category=args.samples
        )
        
        print("\n" + "=" * 70)
        print("COLLECTION COMPLETE")
        print("=" * 70)
        print(f"\nSamples collected: {results['samples_collected']}")
        print(f"\nOutput files:")
        for key, path in results['output_files'].items():
            print(f"  {key}: {path}")
        
        print("\n✓ Data collection successful!")
        return 0
        
    except KeyboardInterrupt:
        print("\n\n⚠ Interrupted by user")
        return 130
        
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1
        
    finally:
        driver.cleanup()


if __name__ == "__main__":
    sys.exit(main())