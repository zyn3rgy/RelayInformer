import contextlib

from impacket import smb3
from impacket.nmb import NetBIOSError
from impacket.smb3 import SMB3
from impacket.smbconnection import SMBConnection
from impacket.smb3structs import (
    SMB2_DIALECT_30,
    SMB2_DIALECT_311,
    SMB2_NEGOTIATE_SIGNING_ENABLED,
    SMB2_NEGOTIATE_SIGNING_REQUIRED,
)

from relayinformer.logger import logger

DIALECT_NAMES = {
    0x0002: "1.0",
    0x0202: "2.0.2",
    0x0210: "2.1",
    0x0300: "3.0",
    0x0302: "3.0.2",
    0x0311: "3.1.1",
}


class SmbInformer:

    def __init__(self, target, port=445, timeout=10):
        self.target = target
        self.port = port
        self.timeout = timeout

    #
    # Perform an unauthenticated SMB NEGOTIATE against the target and read
    #   the server's SecurityMode from the response to determine the message
    #   signing policy. No session is established and no credentials are used.
    #
    # Returns a dict:
    #   dialect  : negotiated dialect name (str)
    #   enabled  : True/False, or None if not determinable
    #   required : True/False, or None if not checked (SMB1)
    #
    def Run(self):
        # Prefer 3.1.1 since that is the dialect modern Windows clients
        # negotiate. Servers that do not support it will reject the
        # single-dialect request, so fall back to a wildcard negotiate
        # that also covers SMB1 and SMB2.
        #
        # Only retry when the server answered but refused the dialect:
        #   - smb3.SessionError: the server sent an error status (for example
        #     STATUS_NOT_SUPPORTED). impacket raises this class here, not
        #     smbconnection.SessionError.
        #   - NetBIOSError: the server closed the connection after the
        #     request, which SMB1-only servers do.
        # A failed TCP connect (refused, unreachable, timeout) raises OSError
        # and is not retried, so an unreachable host fails after one timeout.
        try:
            conn = SMBConnection(self.target, self.target, sess_port=self.port, timeout=self.timeout, preferredDialect=SMB2_DIALECT_311)
        except (smb3.SessionError, NetBIOSError) as e:
            logger.debug(f"{self.target} refused SMB 3.1.1 ({e}), retrying with a wildcard negotiate")
            conn = SMBConnection(self.target, self.target, sess_port=self.port, timeout=self.timeout)
        try:
            inner = conn._SMBConnection
            if isinstance(inner, SMB3):
                dialect = inner._Connection['Dialect']
                if dialect >= SMB2_DIALECT_30:
                    # impacket stores the server's SecurityMode verbatim for
                    # SMB 3.0+. Do not use isSigningRequired() here: impacket
                    # force-sets RequireSigning for 3.1.1 sessions regardless
                    # of the server's policy.
                    security_mode = inner._Connection['ServerSecurityMode']
                    return {
                        "dialect": DIALECT_NAMES.get(dialect, hex(dialect)),
                        "enabled": bool(security_mode & SMB2_NEGOTIATE_SIGNING_ENABLED),
                        "required": bool(security_mode & SMB2_NEGOTIATE_SIGNING_REQUIRED),
                    }
                # SMB 2.0.2/2.1: impacket only stores the required flag
                return {
                    "dialect": DIALECT_NAMES.get(dialect, hex(dialect)),
                    "enabled": None,
                    "required": bool(inner._Connection['RequireSigning']),
                }
            logger.debug(f"{self.target} negotiated SMB1")
            return {
                "dialect": "1.0",
                "enabled": None,
                "required": None,
            }
        finally:
            with contextlib.suppress(Exception):
                conn.close()
