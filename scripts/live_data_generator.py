import os
from pymongo import mongo_client
from data_generator import DataGenerator as DG
from faker import Faker
import time
import random
import uuid

class Live_data_generator:
    
    def __init__(self):
        """
        This creates the constants needed from data_generator BUT 
        internalIPS and usernames will call the methods in data_generator. 
        This script will run infinitely but is only designed to be called from docker
        """
        
        self.fake = Faker() # instace of faker to create fake data
        self.OUTPUT_FOLDER = DG.OUTPUT_FOLDER
        self.OUTPUT_FILE = DG.OUTPUT_FILE
        self.INTERNAL_IPS = DG.INTERNAL_IPS
        self.NUM_logs = DG.NUM_logs
        self.MALICIOUS_IPS = DG.MALICIOUS_IPS
        self.USERNAMES = DG.USERNAMES
        self.HOSTS = DG.HOSTS
        
        print(self.USERNAMES)
        

    ## while forever, kills when docket kills it 
    ## generate data with the weighted scores
    ## write the data to mongoDB
    # i dont think create index?
    ## needs retry loop to check mongoDB is live





def main():
    data_generator = DG()
    LDG = Live_data_generator()
    print("\n\nData stream starting\n\n")

    EVENT_GENERATORS = [
        (data_generator.successful_login_attempt, 40),       # 40% of logs
        (data_generator.failed_login_attempt, 25),           # 25%
        (data_generator.file_access, 15),            # 15%
        (data_generator.powershell_execution, 10),   # 10%
        (data_generator.suspicious_download, 4),     # 4%
        (data_generator.port_scan, 3),               # 3%
        (data_generator.malware_alert, 2),           # 2%
        (data_generator.privilege_escalation, 1),    # 1%
    ]
    
    method = DG.weighted_choice(EVENT_GENERATORS)
    log = method()
    log["log_ID"] = str(uuid.uuid4())
    print(f"\n NEW LOG: \n{log}")

    
if __name__ == "__main__":
    main()