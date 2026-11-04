import socket

WHOAMI_OID = "1.3.6.1.4.1.4203.1.11.3"

RC_NAMES = {
    0:  "success",
    1:  "operationsError",
    8:  "strongerAuthRequired",
    49: "invalidCredentials",
    53: "unwillingToPerform",
}


class LdapBypassInformer:

    def __init__(self, dn, password):
        self.dn = dn
        self.password = password

    # ------------------------------------------------------------------
    # BER encoding
    # ------------------------------------------------------------------

    @staticmethod
    def _ber_len(n):
        if n < 0x80:
            return bytes([n])
        body = b""
        while n:
            body = bytes([n & 0xFF]) + body
            n >>= 8
        return bytes([0x80 | len(body)]) + body

    @staticmethod
    def _tlv(tag, val):
        return bytes([tag]) + LdapBypassInformer._ber_len(len(val)) + val

    @staticmethod
    def _enc_int(n):
        if n == 0:
            body = b"\x00"
        else:
            body = b""
            v = n
            while v:
                body = bytes([v & 0xFF]) + body
                v >>= 8
            if body[0] & 0x80:
                body = b"\x00" + body
        return LdapBypassInformer._tlv(0x02, body)

    @staticmethod
    def _enc_octet(s):
        if isinstance(s, str):
            s = s.encode("utf-8")
        return LdapBypassInformer._tlv(0x04, s)

    @staticmethod
    def _ldap_message(msgid, protocol_op):
        return LdapBypassInformer._tlv(
            0x30,
            LdapBypassInformer._enc_int(msgid) + protocol_op
        )

    @staticmethod
    def _bind_request(dn, pw):
        version = LdapBypassInformer._enc_int(3)
        name = LdapBypassInformer._enc_octet(dn)
        simple = LdapBypassInformer._tlv(0x80, pw.encode("utf-8") if isinstance(pw, str) else pw)
        return LdapBypassInformer._tlv(0x60, version + name + simple)

    @staticmethod
    def _whoami_request():
        return LdapBypassInformer._tlv(0x77, LdapBypassInformer._tlv(0x80, WHOAMI_OID.encode("ascii")))

    @staticmethod
    def _rootdse_search():
        base     = LdapBypassInformer._enc_octet("")
        scope    = LdapBypassInformer._tlv(0x0A, b"\x00")
        deref    = LdapBypassInformer._tlv(0x0A, b"\x00")
        size     = LdapBypassInformer._enc_int(0)
        tim      = LdapBypassInformer._enc_int(0)
        typesonly = LdapBypassInformer._tlv(0x01, b"\x00")
        filt     = LdapBypassInformer._tlv(0x87, b"objectClass")
        attrs    = LdapBypassInformer._tlv(0x30, b"")
        return LdapBypassInformer._tlv(0x63, base + scope + deref + size + tim + typesonly + filt + attrs)

    # ------------------------------------------------------------------
    # BER parsing — just enough to find messageIDs and bind resultCode
    # ------------------------------------------------------------------

    @staticmethod
    def _read_tlv(buf, i):
        if i + 2 > len(buf):
            return None
        tag = buf[i]
        j = i + 1
        l = buf[j]; j += 1
        if l & 0x80:
            nb = l & 0x7F
            if j + nb > len(buf):
                return None
            l = int.from_bytes(buf[j:j + nb], "big")
            j += nb
        if j + l > len(buf):
            return None
        return (tag, j, j + l, j + l)

    _OP_NAMES = {
        0x61: "bindResponse",
        0x64: "searchResEntry",
        0x65: "searchResDone",
        0x67: "modifyResponse",
        0x73: "searchResRef",
        0x78: "extendedResp",
    }

    @staticmethod
    def _parse_messages(buf):
        msgs = []
        i = 0
        while i < len(buf):
            t = LdapBypassInformer._read_tlv(buf, i)
            if t is None or t[0] != 0x30:
                break
            _, vs, ve, nxt = t
            inner = buf[vs:ve]
            it = LdapBypassInformer._read_tlv(inner, 0)
            if it is None:
                break
            itag, ivs, ive, inxt = it
            msgid = int.from_bytes(inner[ivs:ive], "big") if itag == 0x02 else None
            op_tag = inner[inxt] if inxt < len(inner) else None
            rc = None
            if op_tag is not None:
                op = LdapBypassInformer._read_tlv(inner, inxt)
                if op:
                    _, ovs, ove, _ = op
                    e = LdapBypassInformer._read_tlv(inner[ovs:ove], 0)
                    if e and e[0] == 0x0A and (e[2] - e[1]) >= 1:
                        rc = inner[ovs:ove][e[1]:e[2]][0]
            msgs.append({
                "messageID": msgid,
                "op":        op_tag,
                "opName":    LdapBypassInformer._OP_NAMES.get(op_tag, hex(op_tag) if op_tag is not None else None),
                "resultCode": rc,
            })
            i = nxt
        return msgs

    # ------------------------------------------------------------------
    # Network helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _connect(host, port, timeout):
        return socket.create_connection((host, port), timeout=timeout)

    @staticmethod
    def _drain(sock, timeout):
        sock.settimeout(timeout)
        buf = b""
        try:
            while True:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                buf += chunk
        except (socket.timeout, OSError):
            pass
        return buf

    @staticmethod
    def _drain_one(sock, timeout):
        sock.settimeout(timeout)
        buf = b""
        try:
            while True:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                buf += chunk
                if LdapBypassInformer._parse_messages(buf):
                    break
        except (socket.timeout, OSError):
            pass
        return buf

    # ------------------------------------------------------------------
    # Probes
    # ------------------------------------------------------------------

    def probe_stacked(self, host, port, trailing, timeout):
        """Send bind(msgid=1)+trailing(msgid=2) in ONE write; return parsed responses."""
        sock = self._connect(host, port, timeout)
        try:
            op2 = self._whoami_request() if trailing == "whoami" else self._rootdse_search()
            m1 = self._ldap_message(1, self._bind_request(self.dn, self.password))
            m2 = self._ldap_message(2, op2)
            sock.sendall(m1 + m2)
            buf = self._drain(sock, timeout)
        finally:
            try:
                sock.close()
            except Exception:
                pass
        return self._parse_messages(buf), buf

    def probe_nostack(self, host, port, trailing, timeout):
        """Control: bind, drain bind response, THEN send trailing as a separate write."""
        sock = self._connect(host, port, timeout)
        try:
            sock.sendall(self._ldap_message(1, self._bind_request(self.dn, self.password)))
            self._drain_one(sock, timeout)
            op2 = self._whoami_request() if trailing == "whoami" else self._rootdse_search()
            sock.sendall(self._ldap_message(2, op2))
            buf = self._drain(sock, timeout)
        finally:
            try:
                sock.close()
            except Exception:
                pass
        return self._parse_messages(buf), buf

    # ------------------------------------------------------------------
    # Verdict
    # ------------------------------------------------------------------

    @staticmethod
    def verdict_from(msgs):
        bind_rc           = next((m["resultCode"] for m in msgs if m["messageID"] == 1), None)
        trailing_answered = any(m["messageID"] == 2 for m in msgs)
        if trailing_answered:
            return "UNPATCHED", bind_rc, trailing_answered
        if any(m["messageID"] == 1 for m in msgs):
            return "PATCHED", bind_rc, trailing_answered
        return "INCONCLUSIVE", bind_rc, trailing_answered

    # ------------------------------------------------------------------
    # Main entry
    # ------------------------------------------------------------------

    def run(self, host, port, trailing, control, timeout):
        """
        Returns a dict:
          verdict           : "PATCHED" | "UNPATCHED" | "INCONCLUSIVE"
          vulnerable        : bool
          bind_rc           : int | None
          bind_rc_name      : str
          response_pdus     : int
          trailing_answered : bool
          responses         : list[dict]   (raw parsed messages)
          control_answered  : bool | None  (only if control=True)
          error             : str | None
        """
        out = {
            "target":           f"{host}:{port}",
            "trailing":         trailing,
            "error":            None,
            "control_answered": None,
        }

        try:
            msgs, _ = self.probe_stacked(host, port, trailing, timeout)
        except Exception as e:
            out["error"] = f"{type(e).__name__}: {e}"
            return out

        verdict, bind_rc, trailing_answered = self.verdict_from(msgs)
        out["verdict"]           = verdict
        out["vulnerable"]        = (verdict == "UNPATCHED")
        out["bind_rc"]           = bind_rc
        out["bind_rc_name"]      = RC_NAMES.get(bind_rc, str(bind_rc))
        out["response_pdus"]     = len(msgs)
        out["trailing_answered"] = trailing_answered
        out["responses"]         = msgs

        if control:
            try:
                cmsgs, _ = self.probe_nostack(host, port, trailing, timeout)
                out["control_answered"] = any(m["messageID"] == 2 for m in cmsgs)
            except Exception as e:
                out["control_error"] = f"{type(e).__name__}: {e}"

        return out
