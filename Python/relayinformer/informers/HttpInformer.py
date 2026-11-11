from __future__ import annotations

import re
import warnings
import time
from typing import Optional
from urllib.parse import urlparse

import requests
from requests_ntlm import HttpNtlmAuth
import urllib3

from relayinformer.logger import logger


class CustomAvHttpNtlmAuth(HttpNtlmAuth):
    """
    HttpNtlmAuth subclass that allows overriding the server certificate hash,
    and can strip specific AV Pairs from NTLM authentication.
    """

    def __init__(
        self,
        username: str | None,
        password: str | None,
        send_cbt: bool = True,
        custom_cert_hash: bytes | None = None,
        fake_target_name: bool = False,
        strip_target_name: bool = False,
    ) -> None:
        """Create an authentication handler with optional custom certificate hash and AV Pair stripping.
        
        :param str username: Username in 'domain\\username' format
        :param str password: Password
        :param bool send_cbt: Will send the channel bindings over a HTTPS channel (Default: True)
        :param bytes custom_cert_hash: Custom certificate hash to use instead of the server's actual certificate
        :param bool fake_target_name: Use "blah" for both hostname and service in SPNEGO client (Default: False)
        :param bool strip_target_name: Strip the target_name AV Pair from NTLM authentication (Default: False)
        """
        super().__init__(username, password, send_cbt=send_cbt)
        self.custom_cert_hash = custom_cert_hash
        self.fake_target_name = fake_target_name
        self.strip_target_name = strip_target_name
        self.captured_cbt_bytes = None  # Store CBT bytes when captured
        self.captured_target_name = None  # Store target name AV pair when captured
        
        # Apply AV pair stripping patches if requested
        if self.strip_target_name:
            success = patch_spnego_for_av_pair_stripping()
            if not success:
                success = patch_ntlm_client_challenge()
            if not success:
                warnings.warn("Could not enable target_name AV pair stripping")

    def _get_server_cert(self, response: requests.Response) -> bytes | None:
        """
        Override to return custom certificate hash if provided, otherwise use parent implementation.
        Also captures the CBT bytes for later retrieval.
        """
        if self.custom_cert_hash is not None:
            self.captured_cbt_bytes = self.custom_cert_hash
            return self.custom_cert_hash
        
        # Get the actual server certificate and capture it
        cert_bytes = super()._get_server_cert(response)
        self.captured_cbt_bytes = cert_bytes
        return cert_bytes
    
    def retry_using_http_NTLM_auth(self, auth_header_field, auth_header, response, auth_type, args):
        """Override to use fake target name if requested and capture target name AV pair."""
        import spnego
        
        # Capture the target name that would be used
        try:
            parsed_url = urlparse(response.url)
            self.captured_target_name = f"HTTP/{parsed_url.hostname}"
            if self.fake_target_name:
                self.captured_target_name = "BLAH/blah"
        except Exception:
            self.captured_target_name = "UNKNOWN"
        
        # Check if we need fake target name
        if not self.fake_target_name:
            return super().retry_using_http_NTLM_auth(auth_header_field, auth_header, response, auth_type, args)
        
        # Store original client function
        original_client = spnego.client
        
        def patched_client(*args, **kwargs):
            kwargs['hostname'] = "blah"
            kwargs['service'] = "blah"
            return original_client(*args, **kwargs)
        
        # Temporarily patch the spnego.client creation
        spnego.client = patched_client
        try:
            return super().retry_using_http_NTLM_auth(auth_header_field, auth_header, response, auth_type, args)
        finally:
            spnego.client = original_client


def patch_spnego_for_av_pair_stripping():
    """
    Patch the spnego library to strip target_name AV Pairs from NTLM blobs.
    This works by modifying the TargetInfo class to filter out target_name entries.
    """
    try:
        import spnego._ntlm as ntlm_module
        
        # Patch the TargetInfo class to filter out target_name AV pairs
        if hasattr(ntlm_module, 'TargetInfo') and hasattr(ntlm_module, 'AvId'):
            original_pack = ntlm_module.TargetInfo.pack
            
            def patched_pack(self):
                # Remove target_name entries before packing
                if ntlm_module.AvId.target_name in self:
                    del self[ntlm_module.AvId.target_name]
                return original_pack(self)
            
            ntlm_module.TargetInfo.pack = patched_pack
            return True
            
        # Alternative approach: patch TargetInfo.__setitem__ to prevent target_name from being set
        elif hasattr(ntlm_module, 'TargetInfo') and hasattr(ntlm_module, 'AvId'):
            original_setitem = ntlm_module.TargetInfo.__setitem__
            
            def patched_setitem(self, key, value):
                # Skip setting target_name AV pairs
                if key != ntlm_module.AvId.target_name:
                    original_setitem(self, key, value)
            
            ntlm_module.TargetInfo.__setitem__ = patched_setitem
            return True
            
    except (ImportError, AttributeError) as e:
        warnings.warn(f"Could not patch spnego for AV pair stripping: {e}")
        return False
    
    return False


def patch_ntlm_client_challenge():
    """
    Alternative approach: patch the NTClientChallengeV2 class to modify av_pairs.
    """
    try:
        import spnego._ntlm as ntlm_module
        
        if hasattr(ntlm_module, 'NTClientChallengeV2') and hasattr(ntlm_module, 'AvId'):
            original_pack = ntlm_module.NTClientChallengeV2.pack
            
            def patched_pack(self):
                # Filter out target_name from av_pairs before packing
                if hasattr(self, 'av_pairs') and self.av_pairs is not None:
                    if ntlm_module.AvId.target_name in self.av_pairs:
                        del self.av_pairs[ntlm_module.AvId.target_name]
                return original_pack(self)
            
            ntlm_module.NTClientChallengeV2.pack = patched_pack
            return True
            
    except (ImportError, AttributeError) as e:
        warnings.warn(f"Could not patch NTClientChallengeV2: {e}")
        return False
    
    return False





class HttpInformer:
    """
    HTTP/HTTPS informer for testing EPA (Extended Protection for Authentication) settings.
    
    This class handles NTLM authentication testing over HTTP and HTTPS protocols,
    including Channel Binding Token (CBT) manipulation for HTTPS connections.
    """

    def __init__(self, url: str, user: str):
        """
        Initialize HTTP/HTTPS informer
        
        Args:
            url: Target URL (must start with http:// or https://)
            user: Username in format [domain/]username or domain\\username
        """
        self.url = url.rstrip('/')
        self.is_https = url.lower().startswith('https://')
        
        # Parse and validate domain/username
        self.domain, self.username = self.parse_domain_user(user)

    def test_epa_connection(self, password: Optional[str], hashes: Optional[str],
                           send_cbt: bool = True, custom_cert_hash: Optional[bytes] = None,
                           fake_target_name: bool = False, strip_target_name: bool = False) -> tuple[str, Optional[bytes], Optional[str]]:
        """
        Test HTTP/HTTPS connection with specific CBT/AV pair parameters.
        
        Returns:
            Tuple of (result, cbt_bytes, target_name) where:
            - result: 'success', 'unauthorized', 'error'
            - cbt_bytes: Channel binding token bytes (None if not used)
            - target_name: Target name AV pair value
        """
        # Construct full username for requests-ntlm
        if self.domain:
            full_username = f"{self.domain}\\{self.username}"
        else:
            full_username = self.username
            
        # Use password or hashes (pyspnego auto-detects LM:NT format)
        auth_password = password
        if password is None and hashes:
            # Auto-prepend empty LM hash if only NT hash provided (:NTHASH format)
            if hashes.startswith(':'):
                hashes = f"aad3b435b51404eeaad3b435b51404ee{hashes}"

            # Validate hash format: 32hex:32hex (LM:NT)
            if not re.match(r'^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$', hashes):
                logger.error("Invalid hash format - expected LM:NT format (32 hex chars:32 hex chars)")
                return "error", None, None
            # Pass the full hash string - pyspnego auto-detects and uses it
            auth_password = hashes
            logger.debug("Using NTLM hash authentication (pass-the-hash)")
        elif password is None and not hashes:
            logger.error("Either password or hashes must be provided")
            return "error", None, None

        try:
            session = requests.Session()
            
            # For HTTP, CBT should be disabled as it only works over TLS
            effective_send_cbt = send_cbt and self.is_https
            
            auth_handler = CustomAvHttpNtlmAuth(
                full_username,
                auth_password,
                send_cbt=effective_send_cbt,
                custom_cert_hash=custom_cert_hash,
                fake_target_name=fake_target_name,
                strip_target_name=strip_target_name,
            )
            session.auth = auth_handler

            # Only verify TLS for HTTPS requests (always disabled)
            verify_setting = False
            
            # Suppress urllib3 warnings for HTTPS when verification is disabled
            if self.is_https and not verify_setting:
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
            response = session.get(self.url, verify=verify_setting)
            
            # Capture CBT bytes and target name even on auth failures
            cbt_bytes = auth_handler.captured_cbt_bytes if effective_send_cbt else None
            target_name = auth_handler.captured_target_name
            
            if response.status_code == 200:
                logger.debug(f"Successfully authenticated to {self.url}")
                return "success", cbt_bytes, target_name
            elif response.status_code == 401:
                logger.debug(f"Authentication failed with 401 Unauthorized")
                return "unauthorized", cbt_bytes, target_name
            else:
                logger.debug(f"Unexpected response code: {response.status_code}")
                # Return the numeric code as string for callers that need exact status
                return str(response.status_code), cbt_bytes, target_name
                
        except requests.exceptions.SSLError as e:
            logger.debug(f"TLS/SSL error: {e}")
            return "tls_error", None, None
        except requests.exceptions.RequestException as e:
            logger.debug(f"Request error: {e}")
            return "error", None, None



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
            user: Username in format [domain/]username or domain\\username
            
        Returns:
            Tuple of (domain, username)
            
        Raises:
            ValueError: If user format is invalid
        """
        # Handle both / and \ as domain separators
        if '\\' in user:
            domain, username = user.split('\\', 1)
        elif '/' in user:
            domain, username = user.split('/', 1)
        else:
            # No domain specified
            return "", user
        
        if not username:
            raise ValueError("Username must be non-empty")
        
        return domain, username
