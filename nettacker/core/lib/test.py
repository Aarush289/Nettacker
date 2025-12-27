import time
import yaml
from importlib import resources
from Probe_Engine import ProbeEngine
from probes_loader import _probes_by_name
from probes_loader import load_probes_from_yaml
load_probes_from_yaml()

probes = _probes_by_name
port = 80
host = '8.8.8.8'
protocol = "tcp"

engine = ProbeEngine(port , protocol , host , probes)
result = engine.probe_sequentially()

print(f"result is {result}")

