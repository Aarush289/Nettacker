from collections import deque

class ProbeEngine:
    def __init__(self,probes_by_name):
        self.probes_by_name= probes_by_name
        self.probes = list(probes_by_name.value())
        
        
    def get_probes_for_port(self , port:int , protocol:str):
        protocol = protocol.lower()
        specific = []
        for p in self.probes:
            if p.protocol!=protocol:
                continue
            if port in p.ports:
                specific.append(p)
        
        return specific
    
    # def get_probes_for_sslport(self , port:int , protocol:str):
        
            