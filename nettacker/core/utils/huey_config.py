from nettacker.config import Config
from huey import SqliteHuey

print("Huey path:", Config.path.huey_broker)
huey = SqliteHuey(filename = Config.path.huey_broker, results = False)