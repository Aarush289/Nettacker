class BaseExtractor:
    def __init__(self, config):
        self.config = config

    def extract(self, response):
        raise NotImplementedError