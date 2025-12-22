import yaml
import re
import socket
import time

class version_details:
    def __init__(self, raw ,version_template=None , product=None , info=None ,hostname=None,
                 operating_device=None, device_type=None ,
                 cpe_service=None , cpe_os=None , cpe_h=None):
        self.raw = raw
        self.version_template = version_template
        self.product = product
        self.info = info
        self.hostname = hostname
        self.operating_device = operating_device
        self.device_type = device_type
        self.cpe_service = cpe_service
        self.cpe_os = cpe_os
        self.cpe_h = cpe_h
        
        
class Signature:
    def __init__(self , service , regex ,sig_type="match", version_details=None ):
        self.sig_type = sig_type
        self.service = service
        self.regex = regex
        self.version_details = version_details
        
        
class Probe:
    def __init__(self , name , protocol , totalwaits=6000 , tcpwrappedms=3000 ,
                 rarity=5 , ports=None , sslports=None , fallbacks=None ,
                 probe_string="", no_payload=False , Signatures=None):
        self.name = name
        self.protocol = protocol
        self.totalwaits = totalwaits
        self.tcpwrapperdms = tcpwrappedms
        self.rarity = rarity
        self.ports = ports or []
        self.sslports = sslports or []
        self.fallbacks = fallbacks or []
        self.probe_string = probe_string
        self.no_payload = no_payload
        self.Signatures = Signatures or []
        
        
def load_probes_from_yaml(path: str):
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    
    probes_by_name={}
    for p in data["probes"]:
        name = p["name"]
        protocol = p.get("protocol","tcp").lower()
        totalwaits = int(p.get("totalwaits",6000))
        tcpwrappedms = int(p.get("tcpwrappedms",3000))
        rarity = int(p.get("rarity",5))
        ports = p.get("ports",[])
        sslports = p.get("sslports",[])
        fallbacks = p.get("fallbacks",[])
        probe_string = p.get("probe_string","")
        no_payload = p.get("no_payload" ,False)
        
        
        signatures = []
        for s in p.get("signatures",[]):
            sig_type = s.get("type","match")
            service = s.get("service","")
            pattern = s.get("regex","")
            ignore_case = bool(s.get("Ignore_case", False))
            new_line_specifier = bool(s.get("New_line_specifier", False))
            
            
            flags = 0
            if ignore_case:
                flags |= re.IGNORECASE
            if new_line_specifier:
                flags |= re.DOTALL

            regex = re.compile(pattern, flags)
            
            v = s.get("version", {}) or {}
            version = version_details(
                raw=v.get("raw", ""),
                version_template=v.get("version_template", ""),
                product=v.get("product", ""),
                info=v.get("info", ""),
                hostname=v.get("hostname", ""),
                operating_device=v.get("operating_device", ""),
                device_type=v.get("device_type", ""),
                cpe_service=(v.get("cpe", {}) or {}).get("cpe_service", ""),
                cpe_os=(v.get("cpe", {}) or {}).get("cpe_os", ""),
                cpe_h=(v.get("cpe", {}) or {}).get("cpe_h", ""),
            )

            signatures.append(
                Signature(
                    service=service,
                    regex = regex,
                    sig_type=sig_type,
                    version_details = version,
                )
            )
            
        probe = Probe(
            name=name,
            protocol=protocol,
            totalwaits=totalwaits,
            tcpwrappedms=tcpwrappedms,
            rarity=rarity,
            ports=ports,
            sslports=sslports,
            fallbacks=fallbacks,
            probe_string=probe_string,
            no_payload=no_payload,
            Signatures=signatures,
        )
        
        probes_by_name[name] = probe
        
    return probes_by_name
     