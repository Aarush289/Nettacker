import time
import yaml
from importlib import resources
from Probe_Engine import ProbeEngine
from probes_loader import _probes_by_name
from probes_loader import load_probes_from_yaml
load_probes_from_yaml()

probes = _probes_by_name


engine = ProbeEngine(443, "tcp" , "8.8.8.8" , probes)
result = engine.probe_sequentially()

print(f"result is {result}")

