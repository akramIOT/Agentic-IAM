"""
Production Security Hardening and Secrets Management

Comprehensive security hardening, secrets management, and security monitoring
for production deployment of Agentic-IAM.
"""
import os
import secrets
import hashlib
import hmac
import base64
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import jwt
import boto3
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential


class SecretManager:
    """Secure secrets management with multiple backend support"""
    
    def __init__(self, backend: str = "local", **kwargs):
        self.backend = backend
        self.logger = logging.getLogger("security.secrets")
        
        # Initialize backend
        if backend == "aws":
            self.client = boto3.client('secretsmanager', region_name=kwargs.get('region', 'us-west-2'))
        elif backend == "azure":
            vault_url = kwargs.get('vault_url')
            if not vault_url:
                raise ValueError("Azure Key Vault URL required")
            credential = DefaultAzureCredential()
            self.client = SecretClient(vault_url=vault_url, credential=credential)
        elif backend == "local":
            self.secrets_file = kwargs.get('secrets_file', '/app/secrets/secrets.enc')
            self.encryption_key = self._get_encryption_key()
        else:
            raise ValueError(f"Unsupported secrets backend: {backend}")
    
    def _get_encryption_key(self) -> bytes:
        """Get encryption key for local secrets"""
        key_file = Path('/app/secrets/master.key')
        if key_file.exists():
            return key_file.read_bytes()
        else:
            # Generate new key
            key = Fernet.generate_key()
            key_file.parent.mkdir(parents=True, exist_ok=True)
            key_file.write_bytes(key)
            os.chmod(str(key_file), 0o600)
            return key
    
    async def get_secret(self, secret_name: str) -> Optional[str]:
        """Retrieve secret by name"""
        try:
            if self.backend == "aws":
                response = self.client.get_secret_value(SecretId=secret_name)
                return response['SecretString']
            
            elif self.backend == "azure":
                secret = self.client.get_secret(secret_name)
                return secret.value
            
            elif self.backend == "local":
                return self._get_local_secret(secret_name)
            
        except Exception as e:
            self.logger.error(f"Failed to retrieve secret {secret_name}: {e}")
            return None
    
    async def set_secret(self, secret_name: str, secret_value: str) -> bool:
        """Store secret securely"""
        try:
            if self.backend == "aws":
                self.client.create_secret(
                    Name=secret_name,
                    SecretString=secret_value,
                    Description=f"Agentic-IAM secret: {secret_name}"
                )
                return True
            
            elif self.backend == "azure":
                self.client.set_secret(secret_name, secret_value)
                return True
            
            elif self.backend == "local":
                return self._set_local_secret(secret_name, secret_value)
            
        except Exception as e:
            self.logger.error(f"Failed to store secret {secret_name}: {e}")
            return False
    
    def _get_local_secret(self, secret_name: str) -> Optional[str]:
        """Get secret from local encrypted storage"""
        try:
            secrets_file = Path(self.secrets_file)
            if not secrets_file.exists():
                return None
            
            fernet = Fernet(self.encryption_key)
            encrypted_data = secrets_file.read_bytes()
            decrypted_data = fernet.decrypt(encrypted_data)
            secrets_dict = json.loads(decrypted_data.decode())
            
            return secrets_dict.get(secret_name)
            
        except Exception as e:
            self.logger.error(f"Failed to get local secret {secret_name}: {e}")
            return None
    
    def _set_local_secret(self, secret_name: str, secret_value: str) -> bool:
        """Store secret in local encrypted storage"""
        try:
            secrets_file = Path(self.secrets_file)
            secrets_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Load existing secrets
            secrets_dict = {}
            if secrets_file.exists():
                fernet = Fernet(self.encryption_key)
                encrypted_data = secrets_file.read_bytes()
                decrypted_data = fernet.decrypt(encrypted_data)
                secrets_dict = json.loads(decrypted_data.decode())
            
            # Add new secret
            secrets_dict[secret_name] = secret_value
            
            # Encrypt and save
            fernet = Fernet(self.encryption_key)
            encrypted_data = fernet.encrypt(json.dumps(secrets_dict).encode())
            secrets_file.write_bytes(encrypted_data)
            os.chmod(str(secrets_file), 0o600)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to set local secret {secret_name}: {e}")
            return False
    
    async def rotate_secret(self, secret_name: str) -> Optional[str]:
        """Rotate a secret (generate new value)"""
        if secret_name.endswith('_key'):
            # Generate new encryption key
            new_secret = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
        elif secret_name.endswith('_password'):
            # Generate secure password
            new_secret = self.generate_secure_password()
        else:
            # Generate random token
            new_secret = secrets.token_urlsafe(32)
        
        if await self.set_secret(secret_name, new_secret):
            self.logger.info(f"Successfully rotated secret: {secret_name}")
            return new_secret
        
        return None
    
    @staticmethod
    def generate_secure_password(length: int = 32) -> str:
        """Generate cryptographically secure password"""
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
        return ''.join(secrets.choice(alphabet) for _ in range(length))


class SecurityHardening:
    """Production security hardening utilities"""
    
    def __init__(self, settings):
        self.settings = settings
        self.logger = logging.getLogger("security.hardening")
        self.secret_manager = SecretManager(
            backend=settings.secrets_backend if hasattr(settings, 'secrets_backend') else "local"
        )
    
    def validate_security_configuration(self) -> List[str]:
        """Validate security configuration and return issues"""
        issues = []
        
        # Check secret keys
        if self.settings.secret_key == "your-secret-key-change-in-production":
            issues.append("Default secret key in use - CRITICAL SECURITY RISK")
        
        if self.settings.encryption_key == "your-encryption-key-32-chars-long!":
            issues.append("Default encryption key in use - CRITICAL SECURITY RISK")
        
        if self.settings.jwt_secret_key == "jwt-secret-key-change-in-production":
            issues.append("Default JWT secret key in use - CRITICAL SECURITY RISK")
        
        # Check key lengths
        if len(self.settings.secret_key) < 32:
            issues.append("Secret key too short (minimum 32 characters)")
        
        if len(self.settings.encryption_key) != 32:
            issues.append("Encryption key must be exactly 32 characters")
        
        # Check TLS configuration
        if not self.settings.require_tls and self.settings.environment == "production":
            issues.append("TLS not required in production - SECURITY RISK")
        
        # Check audit integrity
        if not self.settings.enable_audit_integrity and self.settings.environment == "production":
            issues.append("Audit log integrity not enabled in production")
        
        # Check database URL security
        if "password" in self.settings.database_url.lower() and not self.settings.database_url.startswith("postgresql"):
            issues.append("Database credentials in URL - consider using secrets")
        
        # Check CORS configuration
        if "*" in self.settings.cors_origins and self.settings.environment == "production":
            issues.append("Wildcard CORS origins in production - SECURITY RISK")
        
        return issues
    
    async def initialize_production_secrets(self) -> bool:
        """Initialize production secrets securely"""
        try:
            secrets_to_generate = [
                "agentic_iam_secret_key",
                "agentic_iam_encryption_key", 
                "agentic_iam_jwt_secret_key",
                "agentic_iam_credential_encryption_key",
                "postgres_password",
                "redis_password",
                "admin_password"
            ]
            
            for secret_name in secrets_to_generate:
                existing = await self.secret_manager.get_secret(secret_name)
                if not existing:
                    if secret_name.endswith("_key"):
                        if "encryption" in secret_name:
                            # 32-byte key for Fernet
                            value = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
                        else:
                            # Regular secret key
                            value = secrets.token_urlsafe(64)
                    else:
                        # Password
                        value = SecretManager.generate_secure_password()
                    
                    await self.secret_manager.set_secret(secret_name, value)
                    self.logger.info(f"Generated new secret: {secret_name}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize production secrets: {e}")
            return False
    
    def setup_file_permissions(self):
        """Set secure file permissions"""
        try:
            # Secure configuration files
            config_files = [
                "/app/config/",
                "/app/secrets/",
                "/app/logs/",
                "/app/data/"
            ]
            
            for path in config_files:
                if os.path.exists(path):
                    if os.path.isdir(path):
                        os.chmod(path, 0o750)  # rwxr-x---
                        for root, dirs, files in os.walk(path):
                            for d in dirs:
                                os.chmod(os.path.join(root, d), 0o750)
                            for f in files:
                                file_path = os.path.join(root, f)
                                if f.endswith(('.key', '.pem', '.cert')):
                                    os.chmod(file_path, 0o600)  # rw-------
                                else:
                                    os.chmod(file_path, 0o640)  # rw-r-----
            
            self.logger.info("File permissions secured")
            
        except Exception as e:
            self.logger.error(f"Failed to set file permissions: {e}")
    
    def generate_ssl_certificates(self, domain: str = "agentic-iam.local") -> bool:
        """Generate self-signed SSL certificates for development"""
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            # Generate certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Agentic-IAM"),
                x509.NameAttribute(NameOID.COMMON_NAME, domain),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=365)
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(domain),
                    x509.DNSName(f"*.{domain}"),
                    x509.DNSName("localhost"),
                    x509.IPAddress("127.0.0.1"),
                ]),
                critical=False,
            ).sign(private_key, hashes.SHA256(), default_backend())
            
            # Save certificates
            ssl_dir = Path("/app/ssl")
            ssl_dir.mkdir(exist_ok=True)
            
            # Private key
            with open(ssl_dir / "tls.key", "wb") as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # Certificate
            with open(ssl_dir / "tls.crt", "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            
            # Set permissions
            os.chmod(ssl_dir / "tls.key", 0o600)
            os.chmod(ssl_dir / "tls.crt", 0o644)
            
            self.logger.info(f"SSL certificates generated for {domain}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to generate SSL certificates: {e}")
            return False


class SecurityMonitoring:
    """Security monitoring and threat detection"""
    
    def __init__(self, settings):
        self.settings = settings
        self.logger = logging.getLogger("security.monitoring")
        
        # Security metrics
        self.failed_auth_attempts = {}
        self.suspicious_ips = set()
        self.rate_limit_violations = {}
        
        # Threat detection thresholds
        self.max_failed_attempts = 10
        self.max_requests_per_minute = 100
        self.suspicious_patterns = [
            r'(?i)(\bunion\b.*\bselect\b)',  # SQL injection
            r'(?i)(<script[^>]*>.*?</script>)',  # XSS
            r'(?i)(javascript:)',  # JavaScript injection
            r'(?i)(data:text/html)',  # Data URI XSS
        ]
    
    def check_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        """Check IP address reputation"""
        # In production, integrate with threat intelligence APIs
        
        result = {
            "ip": ip_address,
            "is_suspicious": False,
            "threats": [],
            "country": None,
            "asn": None
        }
        
        # Check against known suspicious IPs
        if ip_address in self.suspicious_ips:
            result["is_suspicious"] = True
            result["threats"].append("Previously flagged")
        
        # Check private/local IPs
        if ip_address.startswith(('127.', '192.168.', '10.', '172.')):
            result["threats"].append("Private network")
        
        return result
    
    def detect_brute_force(self, ip_address: str, agent_id: str) -> bool:
        """Detect brute force attacks"""
        key = f"{ip_address}:{agent_id}"
        now = datetime.utcnow()
        
        # Initialize tracking
        if key not in self.failed_auth_attempts:
            self.failed_auth_attempts[key] = []
        
        # Add current attempt
        self.failed_auth_attempts[key].append(now)
        
        # Clean old attempts (last hour)
        cutoff = now - timedelta(hours=1)
        self.failed_auth_attempts[key] = [
            t for t in self.failed_auth_attempts[key] if t > cutoff
        ]
        
        # Check threshold
        if len(self.failed_auth_attempts[key]) >= self.max_failed_attempts:
            self.suspicious_ips.add(ip_address)
            self.logger.warning(f"Brute force detected from {ip_address} on agent {agent_id}")
            return True
        
        return False
    
    def check_rate_limiting(self, ip_address: str) -> bool:
        """Check rate limiting violations"""
        now = datetime.utcnow()
        minute_key = now.strftime("%Y-%m-%d-%H-%M")
        key = f"{ip_address}:{minute_key}"
        
        # Track requests per minute
        self.rate_limit_violations[key] = self.rate_limit_violations.get(key, 0) + 1
        
        # Clean old entries
        for old_key in list(self.rate_limit_violations.keys()):
            if old_key.split(':')[1] != minute_key:
                del self.rate_limit_violations[old_key]
        
        # Check threshold
        if self.rate_limit_violations[key] > self.max_requests_per_minute:
            self.logger.warning(f"Rate limiting violation from {ip_address}")
            return True
        
        return False
    
    def scan_for_malicious_patterns(self, content: str) -> List[str]:
        """Scan content for malicious patterns"""
        import re
        
        threats = []
        for pattern in self.suspicious_patterns:
            if re.search(pattern, content):
                threats.append(f"Suspicious pattern detected: {pattern}")
        
        return threats
    
    def generate_security_report(self) -> Dict[str, Any]:
        """Generate security monitoring report"""
        now = datetime.utcnow()
        
        # Calculate metrics
        total_failed_attempts = sum(len(attempts) for attempts in self.failed_auth_attempts.values())
        unique_suspicious_ips = len(self.suspicious_ips)
        
        # Top offending IPs
        ip_attempt_counts = {}
        for key, attempts in self.failed_auth_attempts.items():
            ip = key.split(':')[0]
            ip_attempt_counts[ip] = ip_attempt_counts.get(ip, 0) + len(attempts)
        
        top_ips = sorted(ip_attempt_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            "report_time": now.isoformat(),
            "summary": {
                "total_failed_auth_attempts": total_failed_attempts,
                "unique_suspicious_ips": unique_suspicious_ips,
                "rate_limit_violations": len(self.rate_limit_violations)
            },
            "top_offending_ips": [
                {"ip": ip, "failed_attempts": count} for ip, count in top_ips
            ],
            "suspicious_ips": list(self.suspicious_ips),
            "recommendations": self._generate_security_recommendations()
        }
    
    def _generate_security_recommendations(self) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if len(self.suspicious_ips) > 0:
            recommendations.append("Consider implementing IP-based blocking for repeat offenders")
        
        if len(self.failed_auth_attempts) > 100:
            recommendations.append("High number of failed authentication attempts - review authentication policies")
        
        if len(self.rate_limit_violations) > 50:
            recommendations.append("Consider lowering rate limits or implementing more aggressive throttling")
        
        return recommendations


class ComplianceChecker:
    """Security compliance checking utilities"""
    
    def __init__(self, settings):
        self.settings = settings
        self.logger = logging.getLogger("security.compliance")
    
    def check_gdpr_compliance(self) -> Dict[str, Any]:
        """Check GDPR compliance requirements"""
        compliance_score = 0
        max_score = 10
        issues = []
        
        # Data encryption
        if self.settings.encryption_key and len(self.settings.encryption_key) == 32:
            compliance_score += 2
        else:
            issues.append("Data encryption not properly configured")
        
        # Audit logging
        if self.settings.enable_audit_logging:
            compliance_score += 2
        else:
            issues.append("Audit logging not enabled")
        
        # Data retention
        if hasattr(self.settings, 'audit_retention_days') and self.settings.audit_retention_days <= 365:
            compliance_score += 2
        else:
            issues.append("Data retention policy not configured or too long")
        
        # Access controls
        if self.settings.enable_mfa:
            compliance_score += 2
        else:
            issues.append("Multi-factor authentication not enabled")
        
        # Data integrity
        if self.settings.enable_audit_integrity:
            compliance_score += 2
        else:
            issues.append("Audit log integrity protection not enabled")
        
        return {
            "framework": "GDPR",
            "score": compliance_score,
            "max_score": max_score,
            "percentage": (compliance_score / max_score) * 100,
            "status": "compliant" if compliance_score >= 8 else "non-compliant",
            "issues": issues
        }
    
    def check_hipaa_compliance(self) -> Dict[str, Any]:
        """Check HIPAA compliance requirements"""
        compliance_score = 0
        max_score = 8
        issues = []
        
        # Encryption at rest and in transit
        if self.settings.require_tls and self.settings.encryption_key:
            compliance_score += 2
        else:
            issues.append("Encryption in transit and at rest not properly configured")
        
        # Access controls and authentication
        if self.settings.enable_mfa:
            compliance_score += 2
        else:
            issues.append("Strong authentication not implemented")
        
        # Audit logging
        if self.settings.enable_audit_logging:
            compliance_score += 2
        else:
            issues.append("Comprehensive audit logging not enabled")
        
        # Data integrity
        if self.settings.enable_audit_integrity:
            compliance_score += 2
        else:
            issues.append("Data integrity controls not implemented")
        
        return {
            "framework": "HIPAA",
            "score": compliance_score,
            "max_score": max_score,
            "percentage": (compliance_score / max_score) * 100,
            "status": "compliant" if compliance_score >= 7 else "non-compliant",
            "issues": issues
        }
    
    def check_sox_compliance(self) -> Dict[str, Any]:
        """Check SOX compliance requirements"""
        compliance_score = 0
        max_score = 6
        issues = []
        
        # Financial data protection
        if self.settings.encryption_key:
            compliance_score += 2
        else:
            issues.append("Financial data encryption not configured")
        
        # Access controls
        if self.settings.enable_audit_logging:
            compliance_score += 2
        else:
            issues.append("Access controls and logging not sufficient")
        
        # Change management
        if self.settings.enable_audit_integrity:
            compliance_score += 2
        else:
            issues.append("Change management controls not implemented")
        
        return {
            "framework": "SOX",
            "score": compliance_score,
            "max_score": max_score,
            "percentage": (compliance_score / max_score) * 100,
            "status": "compliant" if compliance_score >= 5 else "non-compliant",
            "issues": issues
        }
    
    def generate_compliance_report(self) -> Dict[str, Any]:
        """Generate comprehensive compliance report"""
        gdpr = self.check_gdpr_compliance()
        hipaa = self.check_hipaa_compliance()
        sox = self.check_sox_compliance()
        
        overall_score = (gdpr["percentage"] + hipaa["percentage"] + sox["percentage"]) / 3
        
        return {
            "generated_at": datetime.utcnow().isoformat(),
            "overall_score": round(overall_score, 2),
            "frameworks": {
                "gdpr": gdpr,
                "hipaa": hipaa,
                "sox": sox
            },
            "recommendations": [
                "Ensure all encryption keys are properly configured",
                "Enable comprehensive audit logging",
                "Implement multi-factor authentication",
                "Configure proper data retention policies",
                "Enable audit log integrity protection"
            ]
        }


# Utility functions for production security
def generate_secure_token(length: int = 32) -> str:
    """Generate cryptographically secure token"""
    return secrets.token_urlsafe(length)

def hash_password(password: str, salt: Optional[bytes] = None) -> Tuple[str, str]:
    """Hash password securely with salt"""
    if salt is None:
        salt = secrets.token_bytes(32)
    
    pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return base64.b64encode(salt).decode(), base64.b64encode(pwdhash).decode()

def verify_password(password: str, salt: str, hash_value: str) -> bool:
    """Verify password against hash"""
    try:
        salt_bytes = base64.b64decode(salt)
        hash_bytes = base64.b64decode(hash_value)
        pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt_bytes, 100000)
        return hmac.compare_digest(pwdhash, hash_bytes)
    except Exception:
        return False

def secure_random_string(length: int = 32, alphabet: str = None) -> str:
    """Generate secure random string with custom alphabet"""
    if alphabet is None:
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    
    return ''.join(secrets.choice(alphabet) for _ in range(length))


# Production security initialization
async def initialize_production_security(settings) -> bool:
    """Initialize all production security measures"""
    try:
        # Security hardening
        hardening = SecurityHardening(settings)
        
        # Check configuration
        issues = hardening.validate_security_configuration()
        if issues:
            logging.error("Security configuration issues found:")
            for issue in issues:
                logging.error(f"  - {issue}")
            
            if any("CRITICAL" in issue for issue in issues):
                logging.error("CRITICAL security issues found - aborting startup")
                return False
        
        # Initialize secrets
        await hardening.initialize_production_secrets()
        
        # Set file permissions
        hardening.setup_file_permissions()
        
        # Generate SSL certificates if needed
        if settings.environment != "production":
            hardening.generate_ssl_certificates()
        
        logging.info("Production security initialization complete")
        return True
        
    except Exception as e:
        logging.error(f"Failed to initialize production security: {e}")
        return False