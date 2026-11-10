from typing import Optional
from impacket import tds

from relayinformer.logger import logger
from relayinformer.lib.MssqlExtended import MSSQLExtended


class MssqlInformer:

    def __init__(self, target: str, user: str, port: int = 1433, **ntlm_kwargs):
        """
        Initialize MSSQL informer
        
        Args:
            target: Target hostname or address
            user: Username in format domain/username
            port: MSSQL port (default 1433)
            **ntlm_kwargs: Additional NTLM parameters:
                - channel_binding_value: Channel binding value for NTLM (default b'')
                - service: Service name for NTLM (default 'MSSQLSvc')
                - strip_target_service: Whether to disable target service AV pair (default False)
        """
        self.target = target
        self.port = port
        
        # Parse and validate domain/username
        self.domain, self.username = self.parse_domain_user(user)
        
        # NTLM customization parameters with defaults
        # Default None means: compute correct CBT on encrypted connections, empty on unencrypted
        self.channel_binding_value = ntlm_kwargs.get('channel_binding_value', None)
        self.service = ntlm_kwargs.get('service', 'MSSQLSvc')
        self.strip_target_service = ntlm_kwargs.get('strip_target_service', False)


    def check_encryption_requirements(self):
        """Check encryption requirements using existing connection. Returns the TDS encryption constant."""
        # Create a fresh connection object for encryption check
        check_ms_sql = MSSQLExtended(self.target, self.port, self.target)
        
        check_ms_sql.connect()
        try:
            resp = check_ms_sql.preLogin()
            encryption_setting = resp['Encryption']
            
            if encryption_setting == tds.TDS_ENCRYPT_REQ:
                logger.info("Server requires encryption (TDS_ENCRYPT_REQ)")
            elif encryption_setting == tds.TDS_ENCRYPT_OFF:
                logger.info("Server supports but does not require encryption (TDS_ENCRYPT_OFF)")
            elif encryption_setting == tds.TDS_ENCRYPT_NOT_SUP:
                logger.info("Server does not support encryption (TDS_ENCRYPT_NOT_SUP)")
            elif encryption_setting == tds.TDS_ENCRYPT_CLIENT_CERT:
                logger.info("Server requires client certificate for encryption (TDS_ENCRYPT_CLIENT_CERT)")
            else:
                logger.info(f"Unknown encryption setting: {encryption_setting}")
            
            return encryption_setting
        finally:
            try:
                check_ms_sql.disconnect()
            except:
                pass


    def test_epa_connection(self, password: Optional[str], hashes: Optional[str], 
                           db: Optional[str], channel_binding_value: Optional[bytes] = None, 
                           service: str = 'MSSQLSvc', strip_target_service: bool = False) -> str:
        """Test login with specific parameters. Returns: 'success', 'untrusted_domain', 'login_failed', 'other'"""
        # Create a fresh connection object for each test to avoid state issues
        test_ms_sql = MSSQLExtended(self.target, self.port, self.target)
        
        # Log appropriate debug message based on test type
        if strip_target_service is True:
            logger.debug("Attempting login with target service AV pair stripped")
        elif service != 'MSSQLSvc':
            logger.debug("Attempting login with incorrect target service AV pair of '%s'", service)

        test_ms_sql.connect()
        try:
            res = test_ms_sql.login(
                database=db, 
                username=self.username, 
                password=password, 
                domain=self.domain, 
                hashes=hashes, 
                useWindowsAuth=True,
                channel_binding_value=channel_binding_value,
                service=service,
                strip_target_service=strip_target_service
            )
            
            if res:
                logger.info(f"Successfully connected to MSSQL server")
                return "success"
            else:
                error_messages = test_ms_sql.getErrorMessages()
                logger.debug(f"Verbose error for determining EPA setting: {error_messages}")
                
                if "The login is from an untrusted domain" in error_messages:
                    return "untrusted_domain"
                elif "Login failed for" in error_messages:
                    return "login_failed"
                else:
                    return "other"
                    
        finally:
            try:
                test_ms_sql.disconnect()
            except:
                pass


    def prereq_check(self, password: Optional[str], hashes: Optional[str], db: Optional[str], encryption_setting: Optional[int] = None) -> bool:
        """Perform initial prerequisite check that valid credentials are supplied (based on expected error or successful authentication)
        This check is important because without valid credentials with EPA (channel and service binding) supported,
        then we cannot assume the enforcement state based on the responses we check moving forward.
        - If encrypted: attempt with valid/default CBT (channel_binding_value=None), expect success or login_failed
        - If unencrypted: attempt with default service, expect success or login_failed
        Returns True if prerequisites satisfied, False otherwise.
        """
        if encryption_setting is None:
            encryption_setting = self.check_encryption_requirements()

        if encryption_setting == tds.TDS_ENCRYPT_REQ:
            logger.debug("Prereq check - encrypted path detected, attempting loginwith valid CBT (default)")
            result = self.test_epa_connection(
                password, hashes, db,
                channel_binding_value=self.channel_binding_value,  # None => compute CBT by default
                service=self.service,
                strip_target_service=False,
            )
        elif encryption_setting == tds.TDS_ENCRYPT_OFF:
            logger.debug("Prereq check - unencrypted path detected, attempting with default target service value")
            result = self.test_epa_connection(
                password, hashes, db,
                channel_binding_value=b'',
                service=self.service,
                strip_target_service=False,
            )
        else:
            logger.error(f"Unsupported or unknown encryption setting for prereq: {encryption_setting}")
            return False

        if result in ("success", "login_failed"):
            logger.info("Prereq check passed with an expected response, continuing")
            logger.debug("Prereq passed with result: %s", result)
            return True

        logger.debug("Prereq failed with result: %s; aborting EPA checks.", result)
        return False

    def test_epa_with_bogus_channel_binding(self, password: Optional[str], hashes: Optional[str], db: Optional[str]) -> str:
        """Test EPA with bogus channel binding value over encrypted connection."""
        logger.debug("Attempting encrypted connection with incorrect channel binding av pair")
        return self.test_epa_connection(
            password, hashes, db, 
            channel_binding_value=b'\xc0\x910\xd2\xc4\xc3\xd4\xc7QZ\xb4R\xdf\x08\xaf\xfd',
            service=self.service,
            strip_target_service=self.strip_target_service
        )


    def test_epa_with_missing_channel_binding(self, password: Optional[str], hashes: Optional[str], db: Optional[str]) -> str:
        """Test EPA with missing channel binding value over encrypted connection."""
        logger.debug("Attempting encrypted connection with stripped channel binding av pair")
        return self.test_epa_connection(
            password, hashes, db, 
            channel_binding_value=b'',
            service=self.service,
            strip_target_service=self.strip_target_service
        )


    def test_epa_with_bogus_target_service(self, password: Optional[str], hashes: Optional[str], db: Optional[str]) -> str:
        """Test EPA with bogus target service over unencrypted connection."""
        return self.test_epa_connection(password, hashes, db, service='cifs', strip_target_service=False)


    def test_epa_with_missing_target_service(self, password: Optional[str], hashes: Optional[str], db: Optional[str]) -> str:
        """Test EPA with missing target service over unencrypted connection."""
        return self.test_epa_connection(password, hashes, db, service='', strip_target_service=True)


    def __enter__(self):
        return self
    

    def __exit__(self, exc_type, exc_val, exc_tb):
        # No persistent connection to clean up
        pass

    
    @staticmethod
    def parse_domain_user(user: str) -> tuple[str, str]:
        """
        Parse and validate domain/username format
        
        Args:
            user: Username in format domain/username
            
        Returns:
            Tuple of (domain, username)
            
        Raises:
            ValueError: If user format is invalid
        """
        if '/' not in user:
            raise ValueError("User must include domain in format 'domain/username'")
        
        domain, username = user.split('/', 1)
        if not domain or not username:
            raise ValueError("Both domain and username must be non-empty")
        
        return domain, username