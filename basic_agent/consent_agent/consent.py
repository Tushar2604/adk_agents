import os
from datetime import datetime, timedelta
from dotenv import load_dotenv
from google.cloud import firestore
from google.api_core.exceptions import GoogleAPICallError
import requests
import logging

# Load environment variables
load_dotenv()

class ConsentAgent:
    def __init__(self):
        # Initialize Firestore client
        self.db = firestore.Client(project=os.getenv('GOOGLE_CLOUD_PROJECT_ID'))
        
        # Collections
        self.consent_collection = os.getenv('FIRESTORE_CONSENT_COLLECTION', 'user_consents')
        self.audit_collection = os.getenv('FIRESTORE_AUDIT_COLLECTION', 'consent_audit_logs')
        
        # Consent rules
        self.required_consents = os.getenv('REQUIRED_CONSENTS', '').split(',')
        self.default_expiry = timedelta(
            days=int(os.getenv('DEFAULT_CONSENT_EXPIRY_DAYS', '365'))
        )

    def verify_consent(self, user_id: str, data_type: str) -> bool:
        """
        Verify if user has valid consent for specific data processing
        
        Args:
            user_id: Unique user identifier
            data_type: Type of data being processed (e.g., 'email', 'credit_card')
        
        Returns:
            bool: True if valid consent exists
        """
        try:
            doc_ref = self.db.collection(self.consent_collection).document(user_id)
            doc = doc_ref.get()
            
            if not doc.exists:
                self._log_audit(user_id, f"No consent document found", False)
                return False
                
            consent_data = doc.to_dict()
            
           
            if not consent_data.get('data_processing', False):
                self._log_audit(user_id, "Global data processing consent missing", False)
                return False
                
            
            type_consent_key = f"{data_type}_consent"
            if type_consent_key in consent_data and not consent_data[type_consent_key]:
                self._log_audit(user_id, f"Specific consent denied for {data_type}", False)
                return False
                
            
            expiry_date = consent_data.get('expiry_date')
            if expiry_date and expiry_date < datetime.utcnow():
                self._log_audit(user_id, "Consent expired", False)
                return False
                
            self._log_audit(user_id, f"Valid consent for {data_type}", True)
            return True
            
        except GoogleAPICallError as e:
            logging.error(f"Consent verification failed: {str(e)}")
            return False

    def register_consent(self, user_id: str, consents: dict) -> bool:
        """
        Register new user consent
        
        Args:
            user_id: Unique user identifier
            consents: Dictionary of consent preferences
                      Example: {'data_processing': True, 'marketing': False}
        
        Returns:
            bool: True if successful
        """
        try:
            doc_ref = self.db.collection(self.consent_collection).document(user_id)
            
            # Prepare consent document
            consent_data = {
                'user_id': user_id,
                'timestamp': datetime.utcnow(),
                'expiry_date': datetime.utcnow() + self.default_expiry,
                **consents
            }
            
            # Validate required consents
            for consent in self.required_consents:
                if consent not in consents:
                    raise ValueError(f"Missing required consent: {consent}")
            
            # Write to Firestore
            doc_ref.set(consent_data)
            self._log_audit(user_id, "New consent registered", True)
            return True
            
        except Exception as e:
            logging.error(f"Consent registration failed: {str(e)}")
            self._log_audit(user_id, f"Consent registration failed: {str(e)}", False)
            return False

    def _log_audit(self, user_id: str, action: str, success: bool):
        """Log consent actions to audit collection"""
        try:
            audit_ref = self.db.collection(self.audit_collection).document()
            audit_ref.set({
                'user_id': user_id,
                'timestamp': datetime.utcnow(),
                'action': action,
                'success': success,
                'service': 'consent_agent'
            })
        except Exception as e:
            logging.error(f"Audit logging failed: {str(e)}")

    def handle_data_violation(self, user_id: str, data_type: str):
        """
        Take action when consent violation is detected
        """
       
        requests.post(
            f"{os.getenv('DATA_DETECTIVE_SERVICE_URL')}/block-processing",
            json={'user_id': user_id}
        )
        
       
        if data_type in ['email', 'phone_number']:
            requests.post(
                f"{os.getenv('DLP_SERVICE_URL')}/redact-data",
                json={'user_id': user_id, 'data_type': data_type}
            )

# Example Usage
if __name__ == "__main__":
    agent = ConsentAgent()
    
    # Register new consent
    agent.register_consent(
        user_id="user123",
        consents={
            'data_processing': True,
            'marketing': False,
            'third_party_sharing': True
        }
    )
    
    # Verify consent
    if agent.verify_consent("user123", "email"):
        print("Valid consent exists")
    else:
        print("Consent missing or invalid")