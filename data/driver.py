"""
Training Data Collection Driver
================================
Orchestrates the complete training data collection process.

This is the "main" script that ties everything together:
1. Initialize browser and feature collector
2. Set up crawler with configuration
3. Collect data from legitimate websites
4. Save training data
5. Prepare data for model training

Think of this as the conductor of an orchestra - it coordinates
all the other modules to work together.

Author: Your Name
Date: 2025
"""

import sys
import os
import json
import argparse
from datetime import datetime

# Add parent directory to path so we can import from src/
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Import our modules
from browser_collector import BrowserCollector
from feature_collector import FeatureCollector
from crawler import WebCrawler, get_popular_websites


class TrainingDataDriver:
    """
    Orchestrates training data collection process.
    
    This class manages the entire pipeline:
    - Component initialization
    - Configuration management
    - Data collection workflow
    - Error handling and recovery
    - Data validation and export
    
    Attributes:
        browser: BrowserCollector instance
        features: FeatureCollector instance
        crawler: WebCrawler instance
        config: Configuration dictionary
        output_dir: Directory for saving data
    """
    
    def __init__(self, headless=True, output_dir='data/training'):
        """
        Initialize the training data driver.
        
        Args:
            headless (bool): Run browser in headless mode (no GUI)
            output_dir (str): Directory to save collected data
        
        Example:
            # Headless mode (production)
            driver = TrainingDataDriver(headless=True)
            
            # Visible browser (debugging)
            driver = TrainingDataDriver(headless=False)
        """
        
        print("=" * 70)
        print("TRAINING DATA COLLECTION - INITIALIZING")
        print("=" * 70)
        
        # ===== CONFIGURATION =====
        self.config = {
            'headless': headless,
            'output_dir': output_dir,
            'min_samples': 50,          # Minimum samples for valid training set
            'target_samples': 100,      # Target number of samples
            'validate_features': True,  # Validate extracted features
            'save_intermediate': True   # Save progress during collection
        }
        
        # ===== CREATE OUTPUT DIRECTORY =====
        self.output_dir = output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            print(f"\n✓ Created output directory: {output_dir}")
        
        # ===== INITIALIZE COMPONENTS =====
        # These will be initialized in setup()
        self.browser = None
        self.features = None
        self.crawler = None
        
        print(f"\nConfiguration:")
        for key, value in self.config.items():
            print(f"  {key}: {value}")
    
    def setup(self):
        """
        Set up all components (browser, feature collector, crawler).
        
        This method:
        1. Initializes BrowserCollector
        2. Creates FeatureCollector
        3. Sets up WebCrawler
        4. Configures crawler settings
        
        Returns:
            bool: True if setup successful, False otherwise
        
        Why separate from __init__?
        - __init__ is lightweight (just config)
        - setup() does heavy initialization (starting browser)
        - Allows creating driver object without starting browser immediately
        - Can retry setup if it fails
        """
        
        print("\n" + "=" * 70)
        print("SETTING UP COMPONENTS")
        print("=" * 70)
        
        try:
            # ===== STEP 1: INITIALIZE BROWSER =====
            print("\n[1/3] Initializing browser...")
            self.browser = BrowserCollector(headless=self.config['headless'])
            
            if not self.browser.initialize_browser():
                print("✗ Browser initialization failed")
                return False
            
            print("✓ Browser ready")
            
            # ===== STEP 2: CREATE FEATURE COLLECTOR =====
            print("\n[2/3] Creating feature collector...")
            self.features = FeatureCollector()
            print("✓ Feature collector ready")
            
            # ===== STEP 3: SET UP CRAWLER =====
            print("\n[3/3] Setting up crawler...")
            self.crawler = WebCrawler(self.browser, self.features)
            
            # Configure crawler
            self.crawler.config.update({
                'delay_between_requests': 3,    # 3 seconds between requests
                'delay_variation': 1,           # ± 1 second random variation
                'max_retries': 2,               # Retry failed pages twice
                'save_interval': 10             # Save every 10 pages
            })
            
            print("✓ Crawler configured")
            print(f"  Delay: {self.crawler.config['delay_between_requests']}s")
            print(f"  Max retries: {self.crawler.config['max_retries']}")
            
            print("\n✓ All components ready!")
            return True
            
        except Exception as e:
            print(f"\n✗ Setup failed: {e}")
            return False
    
    def collect_training_data(self, categories=None, samples_per_category=None):
        """
        Collect training data from multiple website categories.
        
        This is the main data collection method. It:
        1. Generates URL lists from specified categories
        2. Crawls each category
        3. Collects features
        4. Saves results
        5. Validates data quality
        
        Args:
            categories (list): Website categories to crawl
                Default: ['general', 'tech', 'news', 'education']
                Options: Any category from get_popular_websites()
            
            samples_per_category (int): URLs to crawl per category
                Default: 25 (total ~100 samples for 4 categories)
        
        Returns:
            dict: Collection results with statistics
        
        Example:
            driver = TrainingDataDriver()
            driver.setup()
            
            # Collect from all categories
            results = driver.collect_training_data()
            
            # Or specify custom categories
            results = driver.collect_training_data(
                categories=['tech', 'education'],
                samples_per_category=30
            )
        """
        
        # ===== SET DEFAULTS =====
        if categories is None:
            categories = ['general', 'tech', 'news', 'education']
        
        if samples_per_category is None:
            # Calculate to reach target
            samples_per_category = self.config['target_samples'] // len(categories)
        
        print("\n" + "=" * 70)
        print("COLLECTING TRAINING DATA")
        print("=" * 70)
        print(f"\nCategories: {', '.join(categories)}")
        print(f"Samples per category: {samples_per_category}")
        print(f"Total target: {len(categories) * samples_per_category}")
        
        # ===== COLLECT URL LISTS =====
        print("\n" + "-" * 70)
        print("Generating URL lists...")
        print("-" * 70)
        
        all_urls = []
        for category in categories:
            urls = get_popular_websites(category, samples_per_category)
            all_urls.extend(urls)
            print(f"  {category:12} → {len(urls)} URLs")
        
        print(f"\nTotal URLs: {len(all_urls)}")
        
        # ===== CRAWL URLS =====
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = os.path.join(self.output_dir, f'training_data_{timestamp}.json')
        
        print(f"\nStarting crawl...")
        print(f"Output: {output_file}")
        
        summary = self.crawler.crawl_url_list(all_urls, output_file)
        
        # ===== VALIDATE COLLECTED DATA =====
        if self.config['validate_features']:
            print("\n" + "-" * 70)
            print("Validating collected data...")
            print("-" * 70)
            
            validation_results = self._validate_data()
            
            if not validation_results['is_valid']:
                print("\n⚠ WARNING: Data validation issues detected")
                for issue in validation_results['issues']:
                    print(f"  • {issue}")
            else:
                print("\n✓ Data validation passed")
        
        # ===== CHECK IF WE HAVE ENOUGH SAMPLES =====
        samples_collected = len(self.crawler.collected_data)
        
        if samples_collected < self.config['min_samples']:
            print(f"\n⚠ WARNING: Only {samples_collected} samples collected")
            print(f"  Minimum needed: {self.config['min_samples']}")
            print(f"  Consider collecting more data for better model performance")
        else:
            print(f"\n✓ Collected {samples_collected} samples (min: {self.config['min_samples']})")
        
        # ===== EXPORT FEATURE VECTORS =====
        vectors_file = os.path.join(self.output_dir, f'feature_vectors_{timestamp}.json')
        self._export_feature_vectors(vectors_file)
        
        # ===== BUILD RESULTS =====
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
            },
            'validation': validation_results if self.config['validate_features'] else None
        }
        
        # ===== SAVE COLLECTION SUMMARY =====
        summary_file = os.path.join(self.output_dir, f'collection_summary_{timestamp}.json')
        with open(summary_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n💾 Collection summary saved: {summary_file}")
        
        return results
    
    def _validate_data(self):
        """
        Validate collected training data quality.
        
        Checks:
        - Sufficient samples
        - Feature consistency (all samples have same features)
        - No NaN or infinite values
        - Feature value ranges are reasonable
        
        Returns:
            dict: Validation results with issues list
        """
        
        issues = []
        
        # Check sample count
        n_samples = len(self.crawler.collected_data)
        if n_samples == 0:
            issues.append("No data collected")
            return {'is_valid': False, 'issues': issues}
        
        # Get feature vectors
        vectors = self.crawler.get_feature_vectors()
        
        # Check feature consistency
        feature_counts = [len(v) for v in vectors]
        if len(set(feature_counts)) > 1:
            issues.append(f"Inconsistent feature counts: {set(feature_counts)}")
        
        # Check for NaN/infinite values
        import numpy as np
        for i, vector in enumerate(vectors):
            arr = np.array(vector)
            if np.isnan(arr).any():
                issues.append(f"Sample {i} contains NaN values")
            if np.isinf(arr).any():
                issues.append(f"Sample {i} contains infinite values")
        
        # Check feature value ranges (basic sanity check)
        if vectors:
            arr = np.array(vectors)
            
            # Check for suspiciously constant features
            # (all same value might indicate extraction bug)
            for i in range(arr.shape[1]):
                feature_values = arr[:, i]
                if len(set(feature_values)) == 1:
                    issues.append(f"Feature {i} has constant value across all samples")
        
        return {
            'is_valid': len(issues) == 0,
            'issues': issues,
            'n_samples': n_samples,
            'n_features': len(vectors[0]) if vectors else 0
        }
    
    def _export_feature_vectors(self, filepath):
        """
        Export feature vectors in format ready for model training.
        
        Creates a clean JSON file with just the numerical feature vectors
        that can be directly loaded for training.
        
        Args:
            filepath (str): Where to save feature vectors
        """
        
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
        """
        Clean up resources (close browser, etc.).
        
        Always call this when done to prevent:
        - Memory leaks
        - Orphaned browser processes
        - File handle leaks
        
        Example:
            driver = TrainingDataDriver()
            try:
                driver.setup()
                driver.collect_training_data()
            finally:
                driver.cleanup()  # Always runs
        """
        
        print("\n" + "=" * 70)
        print("CLEANING UP")
        print("=" * 70)
        
        if self.browser:
            self.browser.close_browser()
        
        print("✓ Cleanup complete")


# =========================================================================
# COMMAND LINE INTERFACE
# =========================================================================

def main():
    """
    Main function for command-line usage.
    
    Allows running data collection from command line:
    
    python driver.py --categories general tech --samples 30 --headless
    """
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description='Collect training data for browser anomaly detection'
    )
    
    parser.add_argument(
        '--categories',
        nargs='+',
        default=['general', 'tech', 'news', 'education'],
        help='Website categories to crawl (default: general tech news education)'
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
        help='Run browser in visible mode (overrides --headless)'
    )
    
    parser.add_argument(
        '--output',
        default='data/training',
        help='Output directory for collected data (default: data/training)'
    )
    
    args = parser.parse_args()
    
    # Handle visible mode flag
    headless = not args.visible if args.visible else args.headless
    
    # ===== RUN DATA COLLECTION =====
    driver = TrainingDataDriver(
        headless=headless,
        output_dir=args.output
    )
    
    try:
        # Setup components
        if not driver.setup():
            print("\n✗ Setup failed. Exiting.")
            return 1
        
        # Collect data
        results = driver.collect_training_data(
            categories=args.categories,
            samples_per_category=args.samples
        )
        
        # Print final summary
        print("\n" + "=" * 70)
        print("COLLECTION COMPLETE")
        print("=" * 70)
        print(f"\nSamples collected: {results['samples_collected']}")
        print(f"Success rate: {(results['crawl_summary']['successful'] / results['crawl_summary']['total_attempted'] * 100):.1f}%")
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
        # Always cleanup
        driver.cleanup()


# =========================================================================
# TEST/DEMO CODE
# =========================================================================

if __name__ == "__main__":
    # If run directly, execute CLI
    sys.exit(main())