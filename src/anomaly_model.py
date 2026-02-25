
import numpy as np
import pickle
import os
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


class AnomalyDetector:
    
    def __init__(self, contamination=0.1, random_state=42):
        
        self.model = IsolationForest(
            contamination=contamination,  
            random_state=random_state,    
            n_estimators=100,             
            max_samples='auto',           
            max_features=1.0,             
            bootstrap=False,              
            n_jobs=-1,                    
            verbose=0                     
        )
        
        self.scaler = StandardScaler()
        
        self.is_trained = False       
        self.feature_names = []      
        self.training_info = {}       
    
    def train(self, training_data, feature_names=None):
        
        print("=" * 70)
        print("TRAINING ANOMALY DETECTION MODEL")
        print("=" * 70)
        if not isinstance(training_data, np.ndarray):
            training_data = np.array(training_data)
        
        print(f"\nTraining data shape: {training_data.shape}")
        n_samples, n_features = training_data.shape
        MIN_SAMPLES = 50
        if n_samples < MIN_SAMPLES:
            print(f"\n✗ ERROR: Need at least {MIN_SAMPLES} samples")
            print(f"  You have: {n_samples} samples")
            print(f"  Missing: {MIN_SAMPLES - n_samples} samples")
            print("\nSuggestion: Visit more normal websites to collect training data")
            return False
        if np.isnan(training_data).any():
            print("✗ ERROR: Training data contains NaN values")
            return False
        
        if np.isinf(training_data).any():
            print("✗ ERROR: Training data contains infinite values")
            return False
        
        print(f"✓ Data validation passed")
        print(f"  Samples: {n_samples}")
        print(f"  Features: {n_features}")
        
        
        print(f"\nNormalizing features...")
        normalized_data = self.scaler.fit_transform(training_data)
        
        print(f"✓ Features normalized")
        
        if n_samples > 0:
            print(f"\nExample feature transformation:")
            print(f"  Before: {training_data[0][:5]}...")  # First 5 features
            print(f"  After:  {normalized_data[0][:5]}...")
        
        print(f"\nTraining Isolation Forest...")
        print(f"  Trees: {self.model.n_estimators}")
        print(f"  Contamination: {self.model.contamination}")
        self.model.fit(normalized_data)
        
        print(f"✓ Model trained successfully")
        
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
        if not self.is_trained:
            print("ERROR: Model not trained. Call train() first.")
            return None
        if not isinstance(feature_vector, np.ndarray):
            feature_vector = np.array(feature_vector)
        if feature_vector.ndim == 1:
            feature_vector = feature_vector.reshape(1, -1)
        expected_features = len(self.feature_names)
        actual_features = feature_vector.shape[1]
        
        if actual_features != expected_features:
            print(f"ERROR: Expected {expected_features} features, got {actual_features}")
            return None
        
        
        normalized_features = self.scaler.transform(feature_vector)
        
        prediction = self.model.predict(normalized_features)[0]
        
        is_anomaly = (prediction == -1)
        
        decision_score = self.model.decision_function(normalized_features)[0]
        
        confidence = self._score_to_confidence(decision_score, is_anomaly)
        
        result = {
            'is_anomaly': bool(is_anomaly),
            'confidence': round(confidence, 2),
            'raw_score': float(prediction),
            'decision_score': round(float(decision_score), 4)
        }
        
        return result
    
    def _score_to_confidence(self, score, is_anomaly):
        
        if is_anomaly:
            normalized = min(abs(score) / 0.5, 1.0)
        else:
            normalized = min(score / 0.5, 1.0)
        
        confidence = normalized * 100
        
        return max(0, min(100, confidence))
    
    def save_model(self, filepath):
        if not self.is_trained:
            print("ERROR: Cannot save untrained model")
            return False
        
        directory = os.path.dirname(filepath)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)
            print(f"Created directory: {directory}")
        
        model_data = {
            'model': self.model,              
            'scaler': self.scaler,            
            'feature_names': self.feature_names,  
            'training_info': self.training_info,  
            'is_trained': self.is_trained     
        }
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
    
        
        if not os.path.exists(filepath):
            print(f"✗ ERROR: Model file not found: {filepath}")
            return False
        
        try:
            with open(filepath, 'rb') as f:
                model_data = pickle.load(f)
            
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
        if not self.is_trained:
            return None
        return self.training_info.copy()


if __name__ == "__main__":
    print("=" * 70)
    print("ANOMALY DETECTION MODEL - TEST MODE")
    print("=" * 70)
    print("\n[TEST 1] Training Model with Simulated Data")
    print("-" * 70)
    detector = AnomalyDetector(contamination=0.1, random_state=42)
    
    np.random.seed(42)
    
    normal_data = []
    for i in range(60):  # 60 normal samples
        features = [
            np.random.randint(15, 40),      
            np.random.uniform(2.0, 3.0),    
            1,                              
            0,                              
            0,                              
            np.random.randint(0, 2),        
            np.random.randint(2, 6),        
            np.random.uniform(0, 0.3),      
            0,                               
        ] + [np.random.uniform(0, 1) for _ in range(51)] 
        
        normal_data.append(features)
    
    feature_names = [f'feature_{i}' for i in range(60)]
    success = detector.train(normal_data, feature_names)
    
    if not success:
        print("Training failed!")
        exit(1)
    
    print("\n\n[TEST 2] Testing with Normal Website")
    print("-" * 70)
    
    normal_features = [
        22,    
        2.5,   
        1,     
        0,     
        0,     
        1,     
        4,     
        0.2,   
        0,     
    ] + [0.5] * 51 
    
    result = detector.predict(normal_features)
    print(f"\nPrediction:")
    print(f"  Is Anomaly: {result['is_anomaly']}")
    print(f"  Confidence: {result['confidence']:.1f}%")
    print(f"  Decision Score: {result['decision_score']}")
    
    if result['is_anomaly']:
        print("  ⚠ Flagged as anomaly (unexpected!)")
    else:
        print("  ✓ Classified as normal (expected)")
    
    print("\n\n[TEST 3] Testing with Suspicious Website")
    print("-" * 70)
    
    anomalous_features = [
        150,   
        4.8,   
        0,     
        1,     
        1,     
        5,     
        25,    
        0.8,   
        1,     
    ] + [0.9] * 51
    
    result = detector.predict(anomalous_features)
    print(f"\nPrediction:")
    print(f"  Is Anomaly: {result['is_anomaly']}")
    print(f"  Confidence: {result['confidence']:.1f}%")
    print(f"  Decision Score: {result['decision_score']}")
    
    if result['is_anomaly']:
        print("  ✓ Flagged as anomaly (expected)")
    else:
        print("  ⚠ Classified as normal (unexpected!)")
    
    print("\n\n[TEST 4] Save and Load Model")
    print("-" * 70)
    
    
    save_path = 'test_model.pkl'
    if detector.save_model(save_path):
        
        new_detector = AnomalyDetector()
        if new_detector.load_model(save_path):
            
            result = new_detector.predict(normal_features)
            print(f"\nLoaded model prediction:")
            print(f"  Is Anomaly: {result['is_anomaly']}")
            print(f"  Confidence: {result['confidence']:.1f}%")
            
            
            os.remove(save_path)
            print(f"\n✓ Test file removed: {save_path}")
    
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