from nettacker.lib.extractors.json_extractor import JSONExtractor
from nettacker.lib.extractors.regex_extractor import RegexExtractor

def run_extractors(extractors_config, response_text):
    results = {}

    for ext in extractors_config:
        if ext["type"] == "regex":
            extractor = RegexExtractor(ext)
        elif ext["type"] == "json":
            extractor = JSONExtractor(ext)
        else:
            continue

        results[ext["name"]] = list(extractor.extract(response_text))

    return results