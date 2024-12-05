import re
import csv
from collections import Counter, defaultdict

# Function to parse the log file
def parse_log_file(file_path):
    with open(file_path, 'r') as file:
        logs = file.readlines()
    return logs

# Function to count requests per IP
def count_requests_per_ip(logs):
    ip_pattern = r'(\d+\.\d+\.\d+\.\d+)'  # Regex to extract IP address
    ip_counter = Counter(re.findall(ip_pattern, " ".join(logs)))
    return ip_counter

# Function to find the most frequently accessed endpoint
def find_most_accessed_endpoint(logs):
    endpoint_pattern = r'"(?:GET|POST) (/\S*)'  # Regex to extract endpoints
    endpoints = re.findall(endpoint_pattern, " ".join(logs))
    endpoint_counter = Counter(endpoints)
    most_accessed = endpoint_counter.most_common(1)[0] if endpoint_counter else ("None", 0)
    return most_accessed, endpoint_counter

# Function to detect suspicious activity
def detect_suspicious_activity(logs, threshold=10):
    failed_login_pattern = r'(\d+\.\d+\.\d+\.\d+).*"(?:POST|GET) /login.*" 401'  # Regex to extract IPs for failed login attempts
    failed_ips = re.findall(failed_login_pattern, " ".join(logs))
    failed_counter = Counter(failed_ips)
    suspicious_ips = {ip: count for ip, count in failed_counter.items() if count > threshold}
    return suspicious_ips, failed_counter

# Function to save results to a CSV file
def save_results_to_csv(ip_requests, most_accessed, suspicious_activities, output_file='log_analysis_results.csv'):
    with open(output_file, mode='w', newline='') as csv_file:
        writer = csv.writer(csv_file)

        # Write Requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])

        # Write Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed[0], most_accessed[1]])

        # Write Suspicious Activity
        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_activities.items():
            writer.writerow([ip, count])

# Main function to process the log file
def main():
    log_file = 'sample.log'
    logs = parse_log_file(log_file)

    # Count Requests per IP
    ip_requests = count_requests_per_ip(logs)
    print("\nRequests per IP:")
    print(f"{'IP Address':<20} {'Request Count':<15}")
    for ip, count in ip_requests.most_common():
        print(f"{ip:<20} {count:<15}")

    # Identify the Most Accessed Endpoint
    most_accessed, endpoint_counter = find_most_accessed_endpoint(logs)
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    # Detect Suspicious Activity
    suspicious_activities, failed_counter = detect_suspicious_activity(logs)
    print("\nSuspicious Activity Detected:")
    print(f"{'IP Address':<20} {'Failed Login Attempts':<20}")
    for ip, count in suspicious_activities.items():
        print(f"{ip:<20} {count:<20}")

    # Save results to CSV
    save_results_to_csv(ip_requests, most_accessed, suspicious_activities)

if __name__ == "__main__":
    main()
