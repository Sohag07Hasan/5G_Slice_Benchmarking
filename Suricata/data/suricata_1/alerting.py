import json
import requests
from tailer import follow

def call_api(alert_data):
    url = "https://api.example.com/notify"  # API endpoint
    headers = {'Content-Type': 'application/json'}
    response = requests.post(url, headers=headers, json=alert_data)
    print("API Response:", response.text)

def monitor_alerts(logfile):
    for line in follow(open(logfile)):
        try:
            alert = json.loads(line)
            if alert.get('event_type') == 'alert' and 'DoS' in alert.get('alert', {}).get('signature', ''):
                print("DDoS alert detected:", alert)
                #call_api(alert)
        except json.JSONDecodeError:
            continue

if __name__ == "__main__":
    log_file = '/var/log/suricata/eve.json'  # Adjust to your log file location
    monitor_alerts(log_file)
