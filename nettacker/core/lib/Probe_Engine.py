from collections import deque
from probe_sender import tcp_probe,udp_probe,tcp_probe_ssl
from core.lib.probes_loader import version_details
import re 
import string

P_RE = re.compile(r"\$P\((\d+)\)")

SUBST_RE = re.compile(
    r"""\$SUBST\(
        \s*(\d+)\s*,      # group index
        \s*"([^"]*)"\s*, # old string
        \s*"([^"]*)"\s*  # new string
    \)""",
    re.VERBOSE
)

PLACE_RE = re.compile(r"\$(\d+)")

I_RE = re.compile(
    r"""\$I\(
       \s*(\d+)\s*,
       \s*([<>])\s* 
        \)""",
        re.VERBOSE
)


def I(value: bytes, endian: str) -> int:
    """
    Interpret up to 8 bytes as unsigned integer
    endian: '>' = big-endian, '<' = little-endian
    """
    if isinstance(value, str):
        value = value.encode("latin1")

    value = value[:8]  # limit to 8 bytes

    byteorder = "big" if endian == ">" else "little"
    return int.from_bytes(value, byteorder=byteorder, signed=False)

def P(value: bytes | str) -> str:
    """
    Make a string printable:
    - Remove NULLs
    - Keep only printable ASCII
    """
    if isinstance(value, bytes):
        value = value.decode("latin1", errors="ignore")

    return "".join(ch for ch in value if ch in string.printable and ch != "\x00")

def apply_subst(match_obj, regex_match):
    i = int(match_obj.group(1))
    old = match_obj.group(2)
    new = match_obj.group(3)

    value = regex_match.group(i)
    if value is None:
        return ""
    
    if isinstance(value, bytes):
            try:
                value = value.decode("latin1")
            except Exception:
                return ""
    return value.replace(old, new)


def expand_SUBST(template: str, regex_match):
    while True:
        m = SUBST_RE.search(template)
        if not m:
            break
        replacement = apply_subst(m, regex_match)
        template = template[:m.start()] + replacement + template[m.end():]

    return template


def expand_I(template: str, match):
    def repl(m):
        idx = int(m.group(1))
        endian = m.group(2)
        try:
            captured = match.group(idx)
        except IndexError:
            return ""
        return str(I(captured, endian))

    return I_RE.sub(repl, template)


def expand_P(template: str, regex_match):
    def repl(m):
        i = int(m.group(1))
        try:
            return P(regex_match.group(i))
        except IndexError:
            return ""
    return P_RE.sub(repl, template)


def expand_place(template:str , regex_match):
    def repl(m):
        i = int(m.group(1))
        try:
            return regex_match.group(i)
        except IndexError:
            return ""
    return PLACE_RE.sub(repl, template)
    

def expand_template(template: str, regex_match):
    template = expand_SUBST(template, regex_match)
    template = expand_P(template, regex_match)
    template = expand_I(template , regex_match)
    template = expand_place(template , regex_match)
    return template

class result:
    def __init__(self,version_template=None , product=None , info=None ,hostname=None,
                operating_device=None, device_type=None ,
                cpe_service=None , cpe_os=None , cpe_h=None):
        self.version_template = version_template
        self.product = product
        self.info = info
        self.hostname = hostname
        self.operating_device = operating_device
        self.device_type = device_type
        self.cpe_service = cpe_service
        self.cpe_os = cpe_os
        self.cpe_h = cpe_h
        
        
class ProbeEngine:
    def __init__(self,port , protocol ,host,probes_by_name):
        self.probes_by_name= probes_by_name
        self.probes = list(probes_by_name.value())
        self.host = host
        self.port = port
        self.protocol = protocol
        
    def get_probes_for_port(self , port:int , protocol:str):
        protocol = protocol.lower()
        specific = []
        for p in self.probes:
            if p.protocol!=protocol:
                continue
            if port in p.ports:
                specific.append(p)
        
        return specific
    
    def get_probes_for_sslport(self , port:int , protocol:str):
        protocol = protocol.lower()
        specific = []
        for p in self.probes:
            if p.protocol!=protocol:
                continue
            if port in p.sslports:
                specific.append(p)
        return specific
    
    def Match_response(self , response , signature):
            regex = signature.regex
            match = regex.search(response)
            if not match:
                return {"status":False, "result":result()}
            
            version_template = expand_template(version_template, match)
            product          = expand_template(product, match)
            info             = expand_template(info, match)
            hostname         = expand_template(hostname, match)
            operating_device = expand_template(operating_device, match)
            device_type      = expand_template(device_type, match)
            cpe_service      = expand_template(cpe_service, match)
            cpe_os           = expand_template(cpe_os, match)
            cpe_h            = expand_template(cpe_h, match)

            return {
                "status":False,
                "result":result(
                version_template=version_template,
                product=product,
                info=info,
                hostname=hostname,
                operating_device=operating_device,
                device_type=device_type,
                cpe_service=cpe_service,
                cpe_os=cpe_os,
                cpe_h=cpe_h,
            )
        }
                
    
    def check_match_service(self, Signatures , service)->bool:
        for sig_ in Signatures:
            if sig_.service == service:
                return True
        return False
            
    def probe_sequentially(self):
        relevant_probes = self.get_probes_for_port()
        result = {}
        service = None
        flag = False
        for probe in relevant_probes:
            if service == "ssl" and not flag:
                relevant_probes = self.get_probes_for_sslport()
                flag=True
                
            if service != None:
                if self.check_match_service(probe.Signatures , service):
                    continue
                
            if not flag:
                response = tcp_probe(self.host , self.port , probe.payload ,probe.timeout_ms, probe.tcpwrappedms)
            else:
                response = tcp_probe_ssl(self.host , self.port , probe.payload ,probe.timeout_ms, probe.tcpwrappedms)
            tcp_wrap = response.tcp_wrapped
            peer_name = response.peer_name
            raw = response.raw
            decoded_response = response.response
            for signature in probe.Signatures:
                matched_ = self.Match_reponse(decoded_response , signature)
                if matched_.status == False:
                    continue
                if matched_.status == True and signature.sig_type == "match":
                    result = matched_.result
                    return result
                if matched_.status == True and signature.sig_type == "softmatch":
                    service = signature.service
                    result = matched_.result
                    continue
            
            for name in probe.fallbacks:
                _ = self.probes_by_name[name]
                for signature in _.Signatures:
                     matched_ = self.Match_reponse(decoded_response , signature)
                if matched_.status == False:
                    continue
                if matched_.status == True and signature.sig_type == "match":
                    result = matched_.result
                    return result
                if matched_.status == True and signature.sig_type == "softmatch":
                    service = signature.service
                    result = matched_.result
                    continue
    
    
        return result
                
            

        
        