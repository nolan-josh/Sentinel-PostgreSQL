from pymongo import MongoClient
import time


db = client = MongoClient("mongodb://mongoDB:27017/?replicaSet=rs0")["sentinel_ai"] # uses replica 0 for .watch() later on
logs_collection = db['logs']
alerts_collection = db['alerts'] # (alerts collection is created first time we populate it)

## works for listening
connected = False
while not connected:
    try:     
        with alerts_collection.watch() as changes:
                    for change in changes:
                        print(f'change found: {change}')
    except Exception as e:
        print(f"MongoDB not ready, retrying in 3 seconds... ({e})")
        time.sleep(3)
    
