import json
import jq
from nettacker.lib.extractors.base import BaseExtractor
class JSONExtractor(BaseExtractor):
    def __init__(self, config):
        super().__init__(config)
        queries = config.get("json", [])

        if isinstance(queries, str):
            queries = [queries]

        self.queries = [jq.compile(q.strip()) for q in queries]

    def extract(self, text):
        results = set()
        print(f"text is {text}")
        if isinstance(text, dict):
            text = text.get("content", "")
            print(f"text is {text}")
        try:
            json_obj = json.loads(text)
        except Exception as e:
            print(f"I am here as {e}")
            return []

        results = set()
        for query in self.queries:
            try:
                print(f"query is {query}")
                for item in query.input(json_obj).all():
                    if item is not None:
                        results.add(str(item))
            except Exception as e:
                print(f"I am here2 as {e}")
                continue

        return results