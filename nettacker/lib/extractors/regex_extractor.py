import re
from nettacker.lib.extractors.base import BaseExtractor
class RegexExtractor(BaseExtractor):
    def __init__(self, config):
        super().__init__(config)
        self.patterns = [re.compile(r) for r in config.get("regex", [])]
        self.group = config.get("group", 0)

    def extract(self, text):
        results = set()

        for pattern in self.patterns:
            matches = pattern.findall(text)
            for m in matches:
                if isinstance(m, tuple):
                    results.add(m[self.group])
                else:
                    results.add(m)

        return results