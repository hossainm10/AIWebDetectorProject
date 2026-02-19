"""
Anomaly Detection Model Module
==============================
Machine learning model for detecting unusual browsing behavior.

This module uses unsupervised learning (Isolation Forest) to identify anomalies.
Unlike the rule-based analyzer (which checks known patterns), this ML model
learns what "normal" browsing looks like and flags anything that deviates.

Key Concepts:
- Unsupervised Learning: Trains on normal data only (no labels needed)
- Isolation Forest: Algorithm that isolates anomalies instead of profiling normal
- Feature Scaling: Normalizes features so they have equal importance
- Anomaly Score: How "different" something is from normal (-1 to 1)
"""

import numpy as np
import pickle
import os
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


class AnomalyDetector:
    """
    Machine learning model for anomaly detection in browsing behavior.
    
    This class wraps scikit-learn's Isolation Forest algorithm with:
    - Feature normalization (StandardScaler)
    - Model persistence (save/load)
    - Prediction with confidence scores
    - Training data validation
    
    Attributes:
        model: IsolationForest instance
        scaler: StandardScaler for feature normalization
        is_trained: Boolean indicating if model has been trained
        feature_names: List of feature names (for debugging)
        training_info: Metadata about training (date, sample count, etc.)
    """
    
    def __init__(self, contamination=0.1, random_state=42):
        """
        Initialize the anomaly detector.
        
        Args:
            contamination (float): Expected proportion of anomalies (0-0.5)
                - 0.1 = expect 10% of data to be anomalies
                - Lower values make model more sensitive (fewer false positives)
                - Higher values make model less sensitive (catches more anomalies)
            
            random_state (int): Seed for reproducibility
                - Same seed = same results every time
                - Important for debugging and testing
        
        Example:
            # Conservative (fewer false alarms)
            detector = AnomalyDetector(contamination=0.05)
            
            # Aggressive (catches more anomalies)
            detector = AnomalyDetector(contamination=0.15)
        """
        
        # ===== ISOLATION FOREST MODEL =====
        # Isolation Forest works by:
        # 1. Randomly selecting a feature
        # 2. Randomly selecting a split value
        # 3. Creating a tree that isolates points
        # 4. Anomalies are isolated faster (fewer splits needed)
        
        self.model = IsolationForest(
            contamination=contamination,  # Expected anomaly rate
            random_state=random_state,    # For reproducibility
            n_estimators=100,             # Number of trees (more = better but slower)
            max_samples='auto',           # Samples per tree (auto = 256 or n_samples)
            max_features=1.0,             # Features to consider (1.0 = all features)
            bootstrap=False,              # Don't reuse samples
            n_jobs=-1,                    # Use all CPU cores
            verbose=0                     # Suppress output
        )
        
        # Why Isolation Forest?
        # - Works well with high-dimensional data (60+ features)
        # - Fast training and prediction
        # - No need for labeled data (unsupervised)
        # - Effective at catching outliers
        
        # ===== FEATURE SCALER =====
        # StandardScaler transforms features to have:
        # - Mean = 0
        # - Standard deviation = 1
        # This prevents features with large values from dominating
        
        self.scaler = StandardScaler()
        # Example:
        # Before scaling: [url_length: 500, has_https: 1]
        # After scaling:  [url_length: 2.5, has_https: 0.8]
        # Now both features have similar ranges
        
        # ===== STATE TRACKING =====
        self.is_trained = False       # Has model been trained?
        self.feature_names = []       # Names of features (for debugging)
        self.training_info = {}       # Metadata about training
    
    def train(self, training_data, feature_names=None):
        """
        Train the anomaly detection model on normal browsing data.
        
        Training Process:
        1. Validate input data
        2. Normalize features (fit scaler)
        3. Fit Isolation Forest
        4. Store training metadata
        
        Args:
            training_data (list or np.array): Feature vectors from normal browsing
                - Shape: (n_samples, n_features)
                - Example: [[url_len, entropy, ...], [url_len, entropy, ...], ...]
            
            feature_names (list): Names of features (optional, for debugging)
                - Example: ['url_length', 'entropy', 'has_https', ...]
        
        Returns:
            bool: True if training successful, False otherwise
        
        Example:
            # Collect normal browsing data
            detector = AnomalyDetector()
            
            normal_data = [
                [22, 2.5, 1, 0, ...],  # Google.com features
                [18, 2.3, 1, 0, ...],  # GitHub.com features
                [25, 2.8, 1, 0, ...],  # Python.org features
                # ... 50+ more samples
            ]
            
            detector.train(normal_data)
        """
        
        print("=" * 70)
        print("TRAINING ANOMALY DETECTION MODEL")
        print("=" * 70)
        
        # ===== VALIDATE INPUT DATA =====
        
        # Convert to numpy array if needed
        if not isinstance(training_data, np.ndarray):
            training_data = np.array(training_data)
        
        # Check shape
        print(f"\nTraining data shape: {training_data.shape}")
        n_samples, n_features = training_data.shape
        
        # Minimum samples needed for reliable model
        MIN_SAMPLES = 50
        if n_samples < MIN_SAMPLES:
            print(f"\n✗ ERROR: Need at least {MIN_SAMPLES} samples")
            print(f"  You have: {n_samples} samples")
            print(f"  Missing: {MIN_SAMPLES - n_samples} samples")
            print("\nSuggestion: Visit more normal websites to collect training data")
            return False
        
        # Check for NaN or infinite values
        if np.isnan(training_data).any():
            print("✗ ERROR: Training data contains NaN values")
            return False
        
        if np.isinf(training_data).any():
            print("✗ ERROR: Training data contains infinite values")
            return False
        
        print(f"✓ Data validation passed")
        print(f"  Samples: {n_samples}")
        print(f"  Features: {n_features}")
        
        # ===== NORMALIZE FEATURES =====
        # Critical step! Without normalization, features with large values
        # (like url_length: 0-200) would dominate features with small values
        # (like has_https: 0-1)
        
        print(f"\nNormalizing features...")
        
        # fit_transform() does two things:
        # 1. Calculates mean and std for each feature
        # 2. Transforms data using those statistics
        normalized_data = self.scaler.fit_transform(training_data)
        
        print(f"✓ Features normalized")
        
        # Show before/after for first sample (debugging)
        if n_samples > 0:
            print(f"\nExample feature transformation:")
            print(f"  Before: {training_data[0][:5]}...")  # First 5 features
            print(f"  After:  {normalized_data[0][:5]}...")
        
        # ===== TRAIN MODEL =====
        print(f"\nTraining Isolation Forest...")
        print(f"  Trees: {self.model.n_estimators}")
        print(f"  Contamination: {self.model.contamination}")
        
        # fit() builds the forest of isolation trees
        # Each tree learns to isolate points
        # Anomalies need fewer splits to isolate
        self.model.fit(normalized_data)
        
        print(f"✓ Model trained successfully")
        
        # ===== SAVE TRAINING METADATA =====
        self.is_trained = True
        self.feature_names = feature_names if feature_names else [f"feature_{i}" for i in range(n_features)]
        
        self.training_info = {
            'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'n_samples': n_samples,
            'n_features': n_features,
            'contamination': self.model.contamination,
            'n_estimators': self.model.n_estimators
        }
        
        print(f"\nTraining completed:")
        print(f"  Date: {self.training_info['date']}")
        print(f"  Samples: {self.training_info['n_samples']}")
        print(f"  Features: {self.training_info['n_features']}")
        
        print("\n" + "=" * 70)
        
        return True
    
    def predict(self, feature_vector):
        """
        Predict if given features represent anomalous behavior.
        
        Prediction Process:
        1. Validate model is trained
        2. Normalize features using saved scaler
        3. Get prediction from Isolation Forest
        4. Calculate anomaly score
        5. Convert to confidence percentage
        
        Args:
            feature_vector (list or np.array): Single feature vector to analyze
                - Shape: (n_features,)
                - Example: [22, 2.5, 1, 0, ...]
        
        Returns:
            dict: Prediction results containing:
                - is_anomaly: Boolean (True = anomalous, False = normal)
                - confidence: Float 0-100 (how sure the model is)
                - raw_score: Float -1 to 1 (isolation forest score)
                - decision_score: Float (lower = more anomalous)
        
        Example:
            detector = AnomalyDetector()
            # ... train model ...
            
            suspicious_features = [150, 4.8, 0, 1, ...]  # Long URL, high entropy, no HTTPS, IP
            result = detector.predict(suspicious_features)
            
            if result['is_anomaly']:
                print(f"ANOMALY DETECTED! Confidence: {result['confidence']:.1f}%")
            else:
                print(f"Normal behavior. Confidence: {result['confidence']:.1f}%")
        """
        
        # ===== VALIDATE MODEL STATE =====
        if not self.is_trained:
            print("ERROR: Model not trained. Call train() first.")
            return None
        
        # ===== PREPARE INPUT =====
        
        # Convert to numpy array
        if not isinstance(feature_vector, np.ndarray):
            feature_vector = np.array(feature_vector)
        
        # Reshape to 2D array (sklearn expects 2D)
        # From: [1, 2, 3]
        # To:   [[1, 2, 3]]
        if feature_vector.ndim == 1:
            feature_vector = feature_vector.reshape(1, -1)
        
        # Validate feature count
        expected_features = len(self.feature_names)
        actual_features = feature_vector.shape[1]
        
        if actual_features != expected_features:
            print(f"ERROR: Expected {expected_features} features, got {actual_features}")
            return None
        
        # ===== NORMALIZE FEATURES =====
        # IMPORTANT: Use transform(), not fit_transform()
        # We use the same mean/std from training
        # If we fit again, we'd calculate new statistics and break the model
        
        normalized_features = self.scaler.transform(feature_vector)
        
        # ===== GET PREDICTION =====
        
        # predict() returns:
        # -1 = anomaly
        #  1 = normal (inlier)
        prediction = self.model.predict(normalized_features)[0]
        # [0] because we reshaped to 2D, need first (and only) element
        
        is_anomaly = (prediction == -1)
        
        # ===== CALCULATE CONFIDENCE SCORE =====
        
        # score_samples() returns anomaly scores:
        # - Negative scores = anomalies
        # - Positive scores = normal points
        # - More negative = more anomalous
        decision_score = self.model.decision_function(normalized_features)[0]
        
        # Convert to 0-100% confidence
        # This is a heuristic conversion (not statistical probability)
        confidence = self._score_to_confidence(decision_score, is_anomaly)
        
        # ===== BUILD RESULT =====
        result = {
            'is_anomaly': bool(is_anomaly),
            'confidence': round(confidence, 2),
            'raw_score': float(prediction),
            'decision_score': round(float(decision_score), 4)
        }
        
        return result
    
    def _score_to_confidence(self, score, is_anomaly):
        """
        Convert decision score to confidence percentage.
        
        Isolation Forest scores range approximately from -0.5 to 0.5
        We map this to 0-100% confidence.
        
        Args:
            score (float): Decision function score
            is_anomaly (bool): Whether classified as anomaly
        
        Returns:
            float: Confidence percentage (0-100)
        
        Example:
            score = -0.3, is_anomaly = True  → ~80% confidence
            score = 0.2, is_anomaly = False  → ~70% confidence
        """
        
        # Map score from [-0.5, 0.5] to [0, 1]
        # More extreme scores = higher confidence
        
        if is_anomaly:
            # Negative scores (anomalies)
            # -0.5 → 100% confident
            # -0.1 → 60% confident
            normalized = min(abs(score) / 0.5, 1.0)
        else:
            # Positive scores (normal)
            # 0.5 → 100% confident
            # 0.1 → 60% confident
            normalized = min(score / 0.5, 1.0)
        
        # Convert to percentage
        confidence = normalized * 100
        
        # Ensure in range [0, 100]
        return max(0, min(100, confidence))
    
    def save_model(self, filepath):
        """
        Save trained model to disk for later use.
        
        Saves:
        - Isolation Forest model
        - StandardScaler with fitted parameters
        - Feature names
        - Training metadata
        
        Args:
            filepath (str): Path where model should be saved
                - Example: 'models/anomaly_detector.pkl'
        
        Returns:
            bool: True if saved successfully, False otherwise
        
        Example:
            detector.train(normal_data)
            detector.save_model('models/detector.pkl')
            
            # Later, load it back:
            new_detector = AnomalyDetector()
            new_detector.load_model('models/detector.pkl')
        """
        
        if not self.is_trained:
            print("ERROR: Cannot save untrained model")
            return False
        
        # Create directory if it doesn't exist
        directory = os.path.dirname(filepath)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)
            print(f"Created directory: {directory}")
        
        # Package everything needed to restore model
        model_data = {
            'model': self.model,              # The Isolation Forest
            'scaler': self.scaler,            # The StandardScaler
            'feature_names': self.feature_names,  # Feature names
            'training_info': self.training_info,  # Metadata
            'is_trained': self.is_trained     # State flag
        }
        
        # Save using pickle (Python's serialization format)
        try:
            with open(filepath, 'wb') as f:
                pickle.dump(model_data, f)
            
            print(f"✓ Model saved to: {filepath}")
            print(f"  File size: {os.path.getsize(filepath) / 1024:.1f} KB")
            return True
            
        except Exception as e:
            print(f"✗ Error saving model: {e}")
            return False
    
    def load_model(self, filepath):
        """
        Load a previously saved model from disk.
        
        Args:
            filepath (str): Path to saved model file
        
        Returns:
            bool: True if loaded successfully, False otherwise
        
        Example:
            detector = AnomalyDetector()
            if detector.load_model('models/detector.pkl'):
                result = detector.predict(features)
        """
        
        if not os.path.exists(filepath):
            print(f"✗ ERROR: Model file not found: {filepath}")
            return False
        
        try:
            # Load the pickled data
            with open(filepath, 'rb') as f:
                model_data = pickle.load(f)
            
            # Restore model state
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.feature_names = model_data['feature_names']
            self.training_info = model_data['training_info']
            self.is_trained = model_data['is_trained']
            
            print(f"✓ Model loaded from: {filepath}")
            print(f"  Trained: {self.training_info['date']}")
            print(f"  Samples: {self.training_info['n_samples']}")
            print(f"  Features: {self.training_info['n_features']}")
            
            return True
            
        except Exception as e:
            print(f"✗ Error loading model: {e}")
            return False
    
    def get_training_info(self):
        """
        Get information about model training.
        
        Returns:
            dict: Training metadata or None if not trained
        """
        if not self.is_trained:
            return None
        return self.training_info.copy()


# =========================================================================
# TEST CODE
# =========================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("ANOMALY DETECTION MODEL - TEST MODE")
    print("=" * 70)
    
    # ===== TEST 1: Create and Train Model =====
    print("\n[TEST 1] Training Model with Simulated Data")
    print("-" * 70)
    
    # Create detector
    detector = AnomalyDetector(contamination=0.1, random_state=42)
    
    # Simulate normal browsing data (60 features)
    # In real use, this comes from FeatureCollector
    np.random.seed(42)
    
    # Normal websites: consistent patterns
    normal_data = []
    for i in range(60):  # 60 normal samples
        features = [
            np.random.randint(15, 40),      # url_length: short URLs
            np.random.uniform(2.0, 3.0),    # entropy: normal range
            1,                               # is_https: yes
            0,                               # has_ip_address: no
            0,                               # has_suspicious_tld: no
            np.random.randint(0, 2),        # subdomain_count: 0-1
            np.random.randint(2, 6),        # script_count: few scripts
            np.random.uniform(0, 0.3),      # external_link_ratio: low
            0,                               # has_login_form: usually no
            # ... add more features to reach 60 total
        ] + [np.random.uniform(0, 1) for _ in range(51)]  # Pad to 60 features
        
        normal_data.append(features)
    
    # Train the model
    feature_names = [f'feature_{i}' for i in range(60)]
    success = detector.train(normal_data, feature_names)
    
    if not success:
        print("Training failed!")
        exit(1)
    
    # ===== TEST 2: Predict Normal Behavior =====
    print("\n\n[TEST 2] Testing with Normal Website")
    print("-" * 70)
    
    normal_features = [
        22,    # url_length
        2.5,   # entropy
        1,     # is_https
        0,     # has_ip_address
        0,     # has_suspicious_tld
        1,     # subdomain_count
        4,     # script_count
        0.2,   # external_link_ratio
        0,     # has_login_form
    ] + [0.5] * 51  # Pad to 60
    
    result = detector.predict(normal_features)
    print(f"\nPrediction:")
    print(f"  Is Anomaly: {result['is_anomaly']}")
    print(f"  Confidence: {result['confidence']:.1f}%")
    print(f"  Decision Score: {result['decision_score']}")
    
    if result['is_anomaly']:
        print("  ⚠ Flagged as anomaly (unexpected!)")
    else:
        print("  ✓ Classified as normal (expected)")
    
    # ===== TEST 3: Predict Anomalous Behavior =====
    print("\n\n[TEST 3] Testing with Suspicious Website")
    print("-" * 70)
    
    anomalous_features = [
        150,   # url_length: very long
        4.8,   # entropy: high (random-looking)
        0,     # is_https: no (suspicious)
        1,     # has_ip_address: yes (very suspicious)
        1,     # has_suspicious_tld: yes
        5,     # subdomain_count: many
        25,    # script_count: excessive
        0.8,   # external_link_ratio: high
        1,     # has_login_form: yes
    ] + [0.9] * 51  # Pad to 60
    
    result = detector.predict(anomalous_features)
    print(f"\nPrediction:")
    print(f"  Is Anomaly: {result['is_anomaly']}")
    print(f"  Confidence: {result['confidence']:.1f}%")
    print(f"  Decision Score: {result['decision_score']}")
    
    if result['is_anomaly']:
        print("  ✓ Flagged as anomaly (expected)")
    else:
        print("  ⚠ Classified as normal (unexpected!)")
    
    # ===== TEST 4: Save and Load Model =====
    print("\n\n[TEST 4] Save and Load Model")
    print("-" * 70)
    
    # Save model
    save_path = 'test_model.pkl'
    if detector.save_model(save_path):
        
        # Create new detector and load
        new_detector = AnomalyDetector()
        if new_detector.load_model(save_path):
            
            # Test loaded model
            result = new_detector.predict(normal_features)
            print(f"\nLoaded model prediction:")
            print(f"  Is Anomaly: {result['is_anomaly']}")
            print(f"  Confidence: {result['confidence']:.1f}%")
            
            # Cleanup
            os.remove(save_path)
            print(f"\n✓ Test file removed: {save_path}")
    
    # ===== TEST 5: Training Info =====
    print("\n\n[TEST 5] Model Information")
    print("-" * 70)
    
    info = detector.get_training_info()
    if info:
        print(f"Training Date: {info['date']}")
        print(f"Training Samples: {info['n_samples']}")
        print(f"Feature Count: {info['n_features']}")
        print(f"Contamination: {info['contamination']}")
        print(f"Trees: {info['n_estimators']}")
    
    print("\n" + "=" * 70)
    print("✓ All tests complete!")
    print("=" * 70)