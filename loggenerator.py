import random
import time
from datetime import datetime, timedelta

# Parameters for generating fake logs
num_logs = 1000
ip_addresses = ["192.168.0." + str(i) for i in range(1, 255)]
methods = ["GET", "POST", "PUT", "DELETE"]
resources = ["/ranger/login", "/ranger/animals", "/ranger/plants", "/ranger/reports", "/ranger/settings"]
status_codes = [200, 201, 202, 301, 302, 400, 403, 404, 500, 502]
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.71 Safari/537.36",
    "curl/7.68.0",
    "python-requests/2.25.1"
]

# Function to generate a random log entry
def generate_log_entry():
    ip = random.choice(ip_addresses)
    method = random.choice(methods)
    resource = random.choice(resources)
    status = random.choice(status_codes)
    user_agent = random.choice(user_agents)
    timestamp = datetime.now() - timedelta(seconds=random.randint(0, 86400))
    log_entry = f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S %z")}] "{method} {resource} HTTP/1.1" {status} - "{user_agent}"'
    return log_entry

# Generate and write logs to file
with open("park_ranger_server.log", "w") as log_file:
    for i in range(num_logs):
        # Insert a hidden password field into the log file at a random point
        if i == random.randint(1, num_logs - 1):
            print('192.168.0.42 - - [01/May/2024:14:03:15 +0000] "POST /ranger/login HTTP/1.1" 200 - "Mozilla/5.0" "username=Brandon&password=ILoveParkandRecreation2024"\n')
        else:
            print(generate_log_entry() + "\n")

print("Fake log data generated.")
