import os
import json
from pymongo import MongoClient

class Data_handler:
    """ This is a class that will read in 1 or more JSONL files, and add them to a 
    collection of a mongoDB database.
    """
    CLIENT = MongoClient("mongodb://mongoDB:27017")
    DB = CLIENT["sentinel_ai"]
    COLLECTION = DB['logs']

    LOG_FILE = r"../data/Logs/security_log.jsonl"

    def ingest_data(self):
        
        self.COLLECTION.drop() # THIS CLEARS THE ENTIRE DATASET COLLECTION ! 
        
    
        logs, logfiles = [], []
        logfiles.append(self.LOG_FILE)
        print(f"\nlog files to append: {logfiles}\n")
        for LOG in logfiles:
            with open(LOG, "r") as f:
                for line in f:
                    logs.append(json.loads(line.strip()))
                    
        result = self.COLLECTION.insert_many(logs)
        self.COLLECTION.create_index("timestamp")
        self.COLLECTION.create_index("event_type")
        self.COLLECTION.create_index("source_ip")       
        
        print("index created")        
