import os 
from datetime import datetime
import uuid
import asyncio
from pymongo import MongoClient
import json


class ThreatDetector:
    
     # Known "bad" external IPs we'll plant in attack scenarios
    MALICIOUS_IPS = [
        "185.220.101.45",  
        "45.33.32.156",
        "198.20.69.74",
        "89.248.167.131",
    ]
    
    
    
    def __init__(self):
        ## connect to mongo DB | has to us mongoDB not localhost as this is the name for its service in  Docker
        self.db = client = MongoClient("mongodb://mongoDB:27017/?replicaSet=rs0")["sentinel_ai"] # uses replica 0 for .watch() later on
        self.logs_collection = self.db['logs']
        self.alerts_collection = self.db['alerts'] # (alerts collection is created first time we populate it)
        
        
    def detect_brute_force(self):
        """
        _id is the ID to group by,
        count is the total the sum of the entries group by the _id
        addToSet creates a list for everyentry in this above condition
        """
        ## get failed logins grouped by IP
        pipeline = [
        { "$match": { "event_type": "failed_login_attempt" } },
            { 
                "$group": {
                    "_id": "$source_ip",
                    "count": {"$sum": 1},
                    "severities": {"$addToSet": "$severity"},
                    "first_seen": {"$min": "$timestamp"}, 
                    "last_seen": {"$max": "$timestamp"},
                    "affected_hosts": {"$addToSet": "$destination"},
                    "usernames": {"$addToSet": "$username"}
                    }
            }
        ]
        
        aggCursor = self.logs_collection.aggregate(pipeline) # applies the pipeline filters
        alerts = []
        for document in aggCursor:
            if document['count'] > 5:  # Example threshold
                alert = json.dumps(self.__create_alert("brute_force", 
                                  severities=document['severities'], 
                                  affected_hosts=document['affected_hosts'],
                                  source_ip=document['_id'],
                                  username=document['usernames'],
                                  timestamp=document["first_seen"]
                                  ))
                alerts.append(alert) # append not extend since we want to keep the sublist JSON
        return alerts
    
    def detect_malware(self):
        ## get any document in DB is malware_detected
        pipeline = [
        { "$match": { "event_type": "malware_detected" } },
            { 
                "$group": {
                    "_id": "$username",
                    "count": {"$sum": 1},
                    "IP": {"$addToSet": "$source_ip"},
                    "severities": {"$addToSet": "$severity"},
                    "first_seen": {"$min": "$timestamp"}, 
                    "last_seen": {"$max": "$timestamp"},
                    "affected_hosts": {"$addToSet": "$destination"},
                    }
            }
        ]
        aggCursor = self.logs_collection.aggregate(pipeline) # applies the pipeline filters
        alerts = []
        for document in aggCursor:
            alert = json.dumps(self.__create_alert("detect_malware", 
                                severities=document['severities'], 
                                affected_hosts=document['affected_hosts'],
                                source_ip=document['IP'],
                                username=document["_id"],
                                timestamp=document["first_seen"]
                                
                                ))
            alerts.append(alert)
        return alerts

    def detect_privilege_escalation(self):
        ## look for any privilage_escalation
        pipeline = [
        { "$match": { "event_type": "malware_detected" } },
            { 
                "$group": {
                    "_id": "$log_ID",
                    "IP": {"$addToSet": "$source_ip"},
                    "severities": {"$first": "$severity"},
                    "affected_hosts": {"$addToSet": "$destination"},
                    "performed_by_user": {"$addToSet": "$username"},
                    "first_timestamp": {"$min": "$timestamp"},
                    "last_timestamp": {"$max": "$timestamp"}
                    }
            }
        ]
        aggCursor = self.logs_collection.aggregate(pipeline) # applies the pipeline filters
        alerts = []
        for document in aggCursor:
            alert = json.dumps(self.__create_alert("detect_privilge_escalation", 
                                severities=document['severities'], 
                                affected_hosts=document['affected_hosts'],
                                source_ip=document['IP'],
                                username=document["performed_by_user"],
                                timestamp=document["first_timestamp"]
                                ))
            alerts.append(alert)
        return alerts
        
    def detect_port_scans(self):
        # find port scans where source_ip is not in white list or is in blacklist
        ## look for any privilage_escalation where the source IP is blacklist, in future change to not in whitelist
        ## here we dont have a usernamea most of the time
        
        pipeline = [
        { "$match": {"event_type": "port_scan" , 
                     "source_ip": {"$in": self.MALICIOUS_IPS}
                     }},
            { 
                "$group": {
                    "_id": "$log_ID",
                    "IP": {"$addToSet": "$source_ip"},
                    "severities": {"$addToSet": "$severity"},
                    "affected_hosts": {"$addToSet": "$destination"},
                    "performed_by_user": {"$addToSet": {"$ifNull": ["$username", "unkown"]}},
                    "first_timestamp": {"$min": "$timestamp"},
                    "last_timestamp": {"$max": "$timestamp"}
                }
            }
        ]
        aggCursor = self.logs_collection.aggregate(pipeline) # applies the pipeline filters
        alerts = []
        for document in aggCursor:
            alert = json.dumps(self.__create_alert("port_scan", 
                                severities=document['severities'], 
                                affected_hosts=document['affected_hosts'],
                                source_ip=document['IP'],
                                username=document["performed_by_user"],
                                timestamp=document["first_timestamp"]
                                ))
            alerts.append(alert)
        return alerts
        pass
    
    def __create_alert(self, type: str, severities: list[str], affected_hosts: list[str], timestamp: str, source_ip:str = None, username:list[str] = None):
        return {
        "alert_id": str(uuid.uuid4()),
        "event_type": type,
        "severities": severities,
        "source_ip": source_ip,
        "affected_host": affected_hosts,
        "alert_creation": datetime.now().isoformat(),
        "username": username,
        "status": "open",
        "timestamp_start": timestamp,
        }
        
    def run(self):
        """ Calls all the detection methods in sequence, collects all alerts, 
            and does a bulk insert into the alerts collection. Print how many alerts were created at the end.
        """
        alerts = []
        
        alerts.extend(self.detect_privilege_escalation())
        alerts.extend(self.detect_malware())
        alerts.extend(self.detect_brute_force()) #extend since we each JSON element (which is just one json list per element) added to our array
        alerts.extend(self.detect_port_scans())
        
        alert_json_object_list = [json.loads(alert) for alert in alerts]
        
        result = self.alerts_collection.insert_many(alert_json_object_list)
        self.alerts_collection.create_index("status")
        self.alerts_collection.create_index("event_type")
        self.alerts_collection.create_index("alert_creation")       
        self.alerts_collection.create_index("severities")       
        
        print(f"collection created with {len(alerts)} alerts")
        
        return(self.db, self.alerts_collection)
        
        

def main():
    TD = ThreatDetector()
    TD.run()
    
    
    

if __name__ == "__main__":
    main()