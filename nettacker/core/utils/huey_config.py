from nettacker.config import Config
from huey import SqliteHuey


huey = SqliteHuey(filename = Config.path.huey_broker, results = False)
