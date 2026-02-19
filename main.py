"""
Main Application Entry Point
=============================
Orchestrates the entire browser activity analysis system.

This is the central hub that coordinates:
1. Loading configuration
2. Initializing all components
3. Training or loading ML model
4. Analyzing URLs
5. Generating reports

Usage:
    # Analyze single URL
    python main.py --url https://suspicious-site.com
    
    # Analyze URL list
    python main.py --file urls.txt
    
    # Train model first
    python main.py --train --samples 100
    
    # Analyze with custom config
    python main.py --url https://site.com --config config/prod.yaml

Author: Your Name
Date: 2025
"""

import sys
import os
import argparse
from datetime import datetime

# Add src and utils to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'utils'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'data'))

# Import all components
from browser_collector import BrowserCollector
from feature_collector import FeatureCollector
from anomaly_model import AnomalyDetector
from analyzer import RuleBasedAnalyzer
from crawler import WebCrawler, get_popular_websites
from config import Config
from logger import setup_logger
from output import OutputFormatter
from validators import validate_url, ValidationError


class BrowserActivityAnalyzer:
    """
    Main application class that coordinates all components.
    
    This class is the "conductor" that:
    - Initializes all modules
    - Manages application state
    - Coordinates analysis workflow
    - Handles errors gracefully
    
    Attributes:
        config: Configuration object
        logger: Logger instance
        browser: BrowserCollector instance
        features: FeatureCollector instance
        ml_detector: AnomalyDetector instance
        rule_analyzer: RuleBasedAnalyzer instance
        output: OutputFormatter instance
    """
    
    def __init__(self, config_file=None, environment='prod'):
        """
        Initialize the analyzer application.
        
        Args:
            config_file (str): Path to config file
            environment (str): Environment (dev, test, prod)
        
        Example:
            app = BrowserActivityAnalyzer('config/settings.yaml', 'prod')
            app.setup()
            result = app.analyze_url('https://example.com')
        """
        
        print("=" * 70)
        print("BROWSER ACTIVITY ANALYZER")
        print("=" * 70)
        print(f"Initializing... (environment: {environment})")
        
        # ===== LOAD CONFIGURATION =====
        self.config = Config(config_file, environment)
        
        # ===== SETUP LOGGING =====
        self.logger = setup_logger(
            __name__,
            config=self.config.get('logging')
        )
        
        self.logger.info("Application initialized")
        
        # ===== INITIALIZE COMPONENTS =====
        # These will be set up in setup() method
        self.browser = None
        self.features = None
        self.ml_detector = None
        self.rule_analyzer = None
        self.output = None
        
        # Track if components are ready
        self.is_ready = False
    
    def setup(self, train_if_needed=True):
        """
        Set up all application components.
        
        This method:
        1. Initializes browser automation
        2. Creates feature extractor
        3. Loads or trains ML model
        4. Sets up rule-based analyzer
        5. Configures output formatter
        
        Args:
            train_if_needed (bool): Train model if not found
        
        Returns:
            bool: True if setup successful
        
        Example:
            app = BrowserActivityAnalyzer()
            if app.setup():
                # Ready to analyze
                result = app.analyze_url('https://example.com')
        """
        
        self.logger.info("Setting up components...")
        
        try:
            # ===== STEP 1: BROWSER =====
            self.logger.info("[1/5] Initializing browser...")
            
            self.browser = BrowserCollector(
                headless=self.config.get('browser', 'headless')
            )
            
            if not self.browser.initialize_browser():
                self.logger.error("Browser initialization failed")
                return False
            
            self.logger.info("✓ Browser ready")
            
            # ===== STEP 2: FEATURE COLLECTOR =====
            self.logger.info("[2/5] Creating feature collector...")
            
            self.features = FeatureCollector()
            self.logger.info("✓ Feature collector ready")
            
            # ===== STEP 3: ML MODEL =====
            self.logger.info("[3/5] Loading ML model...")
            
            self.ml_detector = AnomalyDetector(
                contamination=self.config.get('model', 'contamination'),
                random_state=self.config.get('model', 'random_state')
            )
            
            # Try to load existing model
            model_path = os.path.join(
                self.config.get('paths', 'models_dir'),
                'anomaly_detector.pkl'
            )
            
            if os.path.exists(model_path):
                self.ml_detector.load_model(model_path)
                self.logger.info(f"✓ ML model loaded from {model_path}")
            else:
                self.logger.warning(f"ML model not found at {model_path}")
                
                if train_if_needed:
                    self.logger.info("Training new model...")
                    if not self._train_model():
                        self.logger.warning("Model training failed, continuing without ML detection")
                else:
                    self.logger.warning("Continuing without ML detection")
            
            # ===== STEP 4: RULE ANALYZER =====
            self.logger.info("[4/5] Setting up rule-based analyzer...")
            
            self.rule_analyzer = RuleBasedAnalyzer()
            self.logger.info("✓ Rule analyzer ready")
            
            
            # ===== STEP 5: OUTPUT FORMATTER =====
            self.logger.info("[5/5] Setting up output formatter...")
            
            self.output = OutputFormatter(
                output_dir=self.config.get('paths', 'reports_dir')
            )
            self.logger.info("✓ Output formatter ready")
            
            # Mark as ready
            self.is_ready = True
            self.logger.info("✓ All components ready!")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Setup failed: {e}", exc_info=True)
            return False
    
    def _train_model(self):
        """
        Train ML model using collected data.
        
        Returns:
            bool: True if training successful
        """
        
        self.logger.info("Collecting training data...")
        
        # Get target sample count
        target_samples = self.config.get('model', 'target_training_samples')
        
        # Create crawler
        crawler = WebCrawler(self.browser, self.features)
        
        # Get normal website URLs
        urls = get_popular_websites('general', target_samples)
        
        # Collect data
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        data_file = os.path.join(
            self.config.get('paths', 'training_dir'),
            f'training_data_{timestamp}.json'
        )
        
        summary = crawler.crawl_url_list(urls, data_file)
        
        # Get feature vectors
        vectors = crawler.get_feature_vectors()
        
        # Check if we have enough samples
        min_samples = self.config.get('model', 'min_training_samples')
        if len(vectors) < min_samples:
            self.logger.error(
                f"Insufficient training data: {len(vectors)} samples "
                f"(minimum: {min_samples})"
            )
            return False
        
        # Train model
        self.logger.info(f"Training model on {len(vectors)} samples...")
        
        if not self.ml_detector.train(vectors):
            self.logger.error("Model training failed")
            return False
        
        # Save model
        model_path = os.path.join(
            self.config.get('paths', 'models_dir'),
            'anomaly_detector.pkl'
        )
        
        self.ml_detector.save_model(model_path)
        self.logger.info(f"✓ Model saved to {model_path}")
        
        return True
    
    def analyze_url(self, url):
        """
        Analyze a single URL for suspicious activity.
        
        This is the main analysis method that:
        1. Validates URL
        2. Visits page with browser
        3. Extracts features
        4. Runs ML detection
        5. Runs rule-based analysis
        6. Combines results
        7. Determines final verdict
        
        Args:
            url (str): URL to analyze
        
        Returns:
            dict: Complete analysis results
        
        Example:
            result = app.analyze_url('https://suspicious-site.com')
            print(f"Risk Level: {result['rule_analysis']['risk_level']}")
            print(f"Verdict: {result['final_verdict']}")
        """
        
        if not self.is_ready:
            raise RuntimeError("Application not initialized. Call setup() first.")
        
        self.logger.info(f"Analyzing URL: {url}")
        
        # ===== STEP 1: VALIDATE URL =====
        is_valid, error = validate_url(url)
        if not is_valid:
            self.logger.error(f"Invalid URL: {error}")
            return {
                'url': url,
                'error': error,
                'final_verdict': 'INVALID URL'
            }
        
        # ===== STEP 2: VISIT PAGE =====
        self.logger.info("Visiting page...")
        
        visit_data = self.browser.visit_url(url)
        if not visit_data:
            self.logger.error("Failed to visit page")
            return {
                'url': url,
                'error': 'Failed to load page',
                'final_verdict': 'ANALYSIS FAILED'
            }
        
        # ===== STEP 3: EXTRACT FEATURES =====
        self.logger.info("Extracting features...")
        
        feature_vector, feature_dict = self.features.extract_all_features(
            url=url,
            driver=self.browser.driver,
            session_history=self.browser.session_history
        )
        
        self.logger.info(f"Extracted {len(feature_vector)} features")
        
        # ===== STEP 4: ML DETECTION =====
        ml_result = None
        
        if self.ml_detector.is_trained and self.config.get('analyzer', 'enable_ml'):
            self.logger.info("Running ML anomaly detection...")
            ml_result = self.ml_detector.predict(feature_vector)
            
            self.logger.info(
                f"ML Result: Anomaly={ml_result['is_anomaly']}, "
                f"Confidence={ml_result['confidence']:.1f}%"
            )
        else:
            self.logger.info("ML detection skipped (not enabled or not trained)")
        
        # ===== STEP 5: RULE-BASED ANALYSIS =====
        rule_result = None
        
        if self.config.get('analyzer', 'enable_rules'):
            self.logger.info("Running rule-based analysis...")
            rule_result = self.rule_analyzer.analyze(feature_dict)
            
            self.logger.info(
                f"Rule Result: Risk={rule_result['risk_level']}, "
                f"Score={rule_result['risk_score']}"
            )
        else:
            self.logger.info("Rule-based analysis skipped (not enabled)")
        
        # ===== STEP 6: DETERMINE FINAL VERDICT =====
        final_verdict = self._determine_verdict(ml_result, rule_result)
        
        self.logger.info(f"Final Verdict: {final_verdict}")
        
        # ===== STEP 7: BUILD RESULT =====
        result = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'visit_info': visit_data,
            'feature_count': len(feature_vector),
            'ml_detection': ml_result,
            'rule_analysis': rule_result,
            'final_verdict': final_verdict
        }
        
        return result
    
    def _determine_verdict(self, ml_result, rule_result):
        """
        Combine ML and rule-based results into final verdict.
        
        Decision logic:
        - Both say dangerous → MALICIOUS - High Confidence
        - ML says anomaly, rules say risky → SUSPICIOUS - High Confidence
        - One says dangerous → SUSPICIOUS - Medium Confidence
        - Both say safe → SAFE
        
        Args:
            ml_result (dict): ML detection results
            rule_result (dict): Rule-based analysis results
        
        Returns:
            str: Final verdict
        """
        
        # Extract key indicators
        ml_anomaly = ml_result.get('is_anomaly', False) if ml_result else False
        ml_confidence = ml_result.get('confidence', 0) if ml_result else 0
        
        risk_level = rule_result.get('risk_level', 'UNKNOWN') if rule_result else 'UNKNOWN'
        risk_score = rule_result.get('risk_score', 0) if rule_result else 0
        
        # Decision tree
        if ml_anomaly and risk_level == 'HIGH':
            return 'MALICIOUS - High Confidence'
        
        elif ml_anomaly and risk_level in ['MEDIUM', 'HIGH']:
            return 'SUSPICIOUS - High Confidence'
        
        elif ml_anomaly or risk_level in ['MEDIUM', 'HIGH']:
            return 'SUSPICIOUS - Medium Confidence'
        
        elif risk_level == 'LOW':
            return 'LOW RISK - Exercise Caution'
        
        elif ml_anomaly == False and risk_level == 'SAFE':
            return 'SAFE'
        
        else:
            return 'INCONCLUSIVE - Manual Review Recommended'
    
    def analyze_url_list(self, urls, save_report=True):
        """
        Analyze multiple URLs.
        
        Args:
            urls (list): List of URLs to analyze
            save_report (bool): Save results to file
        
        Returns:
            list: List of analysis results
        
        Example:
            urls = ['https://site1.com', 'https://site2.com']
            results = app.analyze_url_list(urls)
            
            # Print summary
            for result in results:
                print(f"{result['url']}: {result['final_verdict']}")
        """
        
        self.logger.info(f"Analyzing {len(urls)} URLs...")
        
        results = []
        
        for i, url in enumerate(urls, 1):
            self.logger.info(f"\n[{i}/{len(urls)}] Processing {url}")
            
            try:
                result = self.analyze_url(url)
                results.append(result)
                
            except Exception as e:
                self.logger.error(f"Error analyzing {url}: {e}", exc_info=True)
                results.append({
                    'url': url,
                    'error': str(e),
                    'final_verdict': 'ANALYSIS FAILED'
                })
        
        # Save batch report
        if save_report:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            
            # JSON report
            json_file = self.output.save_json(
                results,
                f'batch_analysis_{timestamp}.json'
            )
            self.logger.info(f"Batch report saved: {json_file}")
            
            # Print summary
            self.output.print_batch_summary(results)
        
        return results
    
    def cleanup(self):
        """
        Clean up resources.
        
        Always call this when done to:
        - Close browser
        - Save any pending data
        - Release resources
        """
        
        self.logger.info("Cleaning up...")
        
        if self.browser:
            self.browser.close_browser()
        
        self.logger.info("✓ Cleanup complete")


# =========================================================================
# COMMAND LINE INTERFACE
# =========================================================================

def main():
    """
    Main function for command-line usage.
    
    Examples:
        # Analyze single URL
        python main.py --url https://suspicious-site.com
        
        # Analyze URL list
        python main.py --file urls.txt
        
        # Train model
        python main.py --train --samples 100
        
        # Use custom config
        python main.py --url https://site.com --config config/prod.yaml
    """
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description='AI-Powered Browser Activity Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Analyze single URL:
    python main.py --url https://suspicious-site.com
  
  Analyze list of URLs:
    python main.py --file urls.txt
  
  Train model first:
    python main.py --train --samples 100
  
  Use custom configuration:
    python main.py --url https://site.com --config config/prod.yaml
        """
    )
    
    # Mode selection
    parser.add_argument(
        '--url',
        help='Single URL to analyze'
    )
    
    parser.add_argument(
        '--file',
        help='File containing URLs (one per line)'
    )
    
    parser.add_argument(
        '--train',
        action='store_true',
        help='Train ML model before analyzing'
    )
    
    # Configuration
    parser.add_argument(
        '--config',
        help='Path to config file (YAML or JSON)'
    )
    
    parser.add_argument(
        '--env',
        default='prod',
        choices=['dev', 'test', 'prod'],
        help='Environment (default: prod)'
    )
    
    # Training options
    parser.add_argument(
        '--samples',
        type=int,
        default=100,
        help='Number of training samples to collect (default: 100)'
    )
    
    # Output options
    parser.add_argument(
        '--output',
        help='Output file for results'
    )
    
    parser.add_argument(
        '--format',
        choices=['json', 'csv', 'html'],
        default='json',
        help='Output format (default: json)'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Verbose output'
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.url and not args.file and not args.train:
        parser.error('Must specify --url, --file, or --train')
    
    # ===== INITIALIZE APPLICATION =====
    try:
        app = BrowserActivityAnalyzer(
            config_file=args.config,
            environment=args.env
        )
        
        # Override config with command line args
        if args.verbose:
            app.config.set('logging', 'level', value='DEBUG')
        
        # Setup components
        if not app.setup(train_if_needed=args.train):
            print("✗ Setup failed")
            return 1
        
        # ===== EXECUTE REQUESTED ACTION =====
        
        if args.train:
            # Training mode
            print("\n" + "=" * 70)
            print("TRAINING ML MODEL")
            print("=" * 70)
            
            if app._train_model():
                print("✓ Model training complete")
            else:
                print("✗ Model training failed")
                return 1
        
        if args.url:
            # Single URL analysis
            print("\n" + "=" * 70)
            print("ANALYZING SINGLE URL")
            print("=" * 70)
            
            result = app.analyze_url(args.url)
            
            # Display result
            app.output.print_analysis_summary(result)
            
            # Save if requested
            if args.output:
                if args.format == 'json':
                    app.output.save_json(result, args.output)
                elif args.format == 'html':
                    app.output.save_html_report(result, args.output)
                
                print(f"\n✓ Results saved to: {args.output}")
        
        elif args.file:
            # Batch URL analysis
            print("\n" + "=" * 70)
            print("BATCH URL ANALYSIS")
            print("=" * 70)
            
            # Load URLs from file
            with open(args.file, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            
            print(f"Loaded {len(urls)} URLs from {args.file}")
            
            # Analyze all
            results = app.analyze_url_list(urls)
            
            # Save if requested
            if args.output:
                if args.format == 'json':
                    app.output.save_json(results, args.output)
                elif args.format == 'csv':
                    # Convert to CSV-friendly format
                    csv_data = [
                        {
                            'url': r['url'],
                            'verdict': r['final_verdict'],
                            'risk_score': r.get('rule_analysis', {}).get('risk_score', 'N/A'),
                            'ml_anomaly': r.get('ml_detection', {}).get('is_anomaly', 'N/A')
                        }
                        for r in results
                    ]
                    app.output.save_csv(csv_data, args.output)
                
                print(f"\n✓ Results saved to: {args.output}")
        
        print("\n✓ Analysis complete!")
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
        if 'app' in locals():
            app.cleanup()


if __name__ == "__main__":
    sys.exit(main())