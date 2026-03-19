import json
from pathlib import Path
from threading import Lock
from nettacker.config import Config



class APIKeyManager:
    def __init__(self):
        self.lock = Lock()
        self.file_path = Config.api.api_keys_file
        self.keys = self._load()

    def _load(self):
        if self.file_path.exists():
            try:
                with open(self.file_path, "r") as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save(self):
        with open(self.file_path, "w") as f:
            json.dump(self.keys, f, indent=2)

    def set(self, service, value):
        with self.lock:
            self.keys[service] = value
            self._save()

    def get(self, service):
        return self.keys.get(service)

    def delete(self, service):
        with self.lock:
            if service in self.keys:
                del self.keys[service]
                self._save()


# global instance
api_key_manager = APIKeyManager()