import re
import csv
from collections import defaultdict

# Function to parse the log file and extract relevant data
def parse_log(file_path):
    ip_requests = defaultdict(int)
    endpoints = defaultdict(int)
    failed_logins = defaultdict(int)

    # Read the log file
    with open(file_path, 'r') as file:
        for line in file:
            # Extract IP address
            ip_address = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            if ip_address:
                ip_requests[ip_address.group(0)] += 1

            # Extract the endpoint
            endpoint = re.search(r'\"(?:GET|POST|PUT|DELETE|PATCH) (\S+)', line)
            if endpoint:
                endpoints[endpoint.group(1)] += 1

            # Detect failed login attempts
            if 'Invalid credentials' in line or ' 401 ' in line:
                ip_address = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if ip_address:
                    failed_logins[ip_address.group(0)] += 1

    return ip_requests, endpoints, failed_logins

# Function to sort and display the results
def display_results(ip_requests, endpoints, failed_logins, login_threshold):
    # Sort and display IP requests
    print("\nIP Address Request Count:")
    print(f"{'IP Address':<20} {'Request Count'}")
    sorted_ip_requests = sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)
    for ip, count in sorted_ip_requests:
        print(f"{ip:<20} {count}")

    # Display most accessed endpoint
    most_accessed_endpoint = max(endpoints.items(), key=lambda x: x[1])
    print(f"\nMost Frequently Accessed Endpoint:\n{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    # Detect suspicious activity
    print(f"\nSuspicious Activity Detected (Failed Login Attempts > {login_threshold}):")
    print(f"{'IP Address':<20} {'Failed Login Attempts'}")
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > login_threshold}
    for ip, count in suspicious_ips.items():
        print(f"{ip:<20} {count}")

# Function to save the results to a CSV file
def save_to_csv(ip_requests, endpoints, failed_logins):
    with open('log_analysis_results.csv', 'w', newline='') as file:
        writer = csv.writer(file)

        # Writing IP Requests
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])

        # Writing Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(['Endpoint', 'Access Count'])
        for endpoint, count in endpoints.items():
            writer.writerow([endpoint, count])

        # Writing Suspicious Activity
        writer.writerow([])
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in failed_logins.items():
            writer.writerow([ip, count])

# Main function to run the analysis
def main():
    log_file = 'sample.log'  # Path to the log file
    login_threshold = 10  # Set the threshold for suspicious activity

    # Parse the log file
    ip_requests, endpoints, failed_logins = parse_log(log_file)

    # Display the results
    display_results(ip_requests, endpoints, failed_logins, login_threshold)

    # Save the results to CSV
    save_to_csv(ip_requests, endpoints, failed_logins)
    print("\nResults saved to 'log_analysis_results.csv'.")

if __name__ == "__main__":
    main()
