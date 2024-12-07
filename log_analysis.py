from collections import Counter

def count_requests_per_ip(log_file):
    # Dictionary to store request counts per IP
    request_counts = Counter()

    try:
        with open(log_file, "r") as file:
            for line in file:
                # Extract the IP address (first segment of each log entry)
                ip_address = line.split()[0]
                request_counts[ip_address] += 1

        # Sort IP addresses by request count in descending order
        sorted_counts = sorted(request_counts.items(), key=lambda x: x[1], reverse=True)

        # Display results
        print(f"{'IP Address':<20}{'Request Count':<15}")
        print("-" * 35)
        for ip, count in sorted_counts:
            print(f"{ip:<20}{count:<15}")

    except FileNotFoundError:
        print(f"Error: File '{log_file}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

# Specify the log file name
log_file_name = "sample.log"

# Call the function
count_requests_per_ip(log_file_name)
from collections import Counter

#Define the most frequently accessed endpoint
def find_most_frequent_endpoint(log_file):
    # Dictionary to store access counts per endpoint
    endpoint_counts = Counter()

    try:
        with open(log_file, "r") as file:
            for line in file:
                # Extract the endpoint (part of the log between the HTTP method and HTTP version)
                parts = line.split('"')
                if len(parts) > 1:
                    request = parts[1]
                    endpoint = request.split()[1]
                    endpoint_counts[endpoint] += 1

        # Find the most frequently accessed endpoint
        most_frequent = max(endpoint_counts.items(), key=lambda x: x[1])

        # Display results
        print("Most Frequently Accessed Endpoint:")
        print(f"{most_frequent[0]} (Accessed {most_frequent[1]} times)")

    except FileNotFoundError:
        print(f"Error: File '{log_file}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

# Specify the log file name
log_file_name = "sample.log"

# Call the function
find_most_frequent_endpoint(log_file_name)
from collections import Counter

def detect_suspicious_activity(log_file, threshold=10):
    # Counter for failed login attempts per IP address
    failed_attempts = Counter()

    try:
        with open(log_file, "r") as file:
            for line in file:
                # Check if the line contains evidence of a failed login attempt
                if "401" in line or "Invalid credentials" in line:
                    # Extract the IP address (first part of the line before the "- -")
                    ip_address = line.split()[0]
                    failed_attempts[ip_address] += 1

        # Filter IPs exceeding the threshold
        flagged_ips = {ip: count for ip, count in failed_attempts.items() if count > threshold}

        # Display results
        if flagged_ips:
            print("Suspicious Activity Detected:")
            print(f"{'IP Address':<20}{'Failed Login Attempts':<10}")
            for ip, count in flagged_ips.items():
                print(f"{ip:<20}{count:<10}")
        else:
            print("No suspicious activity detected.")

    except FileNotFoundError:
        print(f"Error: File '{log_file}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

# To specify the log file name
log_file_name = "sample.log"

# Call the function with threshold
detect_suspicious_activity(log_file_name, threshold=10)
import csv
from collections import Counter

# Function to count requests per IP
def count_requests_per_ip(log_file):
    ip_counter = Counter()
    with open(log_file, "r") as file:
        for line in file:
            ip_address = line.split()[0]
            ip_counter[ip_address] += 1
    return ip_counter

# Function to find the most frequently accessed endpoint
def find_most_accessed_endpoint(log_file):
    endpoint_counter = Counter()
    with open(log_file, "r") as file:
        for line in file:
            if '"' in line:
                parts = line.split('"')
                request = parts[1].split() if len(parts) > 1 else []
                if len(request) > 1:
                    endpoint = request[1]
                    endpoint_counter[endpoint] += 1
    most_accessed = endpoint_counter.most_common(1)
    return most_accessed[0] if most_accessed else ("None", 0)

# Defining the function to detect suspicious activity
def detect_suspicious_activity(log_file, threshold=10):
    failed_attempts = Counter()
    with open(log_file, "r") as file:
        for line in file:
            if "401" in line or "Invalid credentials" in line:
                ip_address = line.split()[0]
                failed_attempts[ip_address] += 1
    flagged_ips = {ip: count for ip, count in failed_attempts.items() if count > threshold}
    return flagged_ips

# Defining the function to write results to CSV
def write_results_to_csv(ip_counts, most_accessed_endpoint, suspicious_ips, output_file):
    with open(output_file, mode="w", newline="") as file:
        writer = csv.writer(file)

        # Write Requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_counts.items():
            writer.writerow([ip, count])
        writer.writerow([])  # Empty row for spacing

        # Write Most Accessed Endpoint
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])
        writer.writerow([])

        # Write Suspicious Activity
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

# Defining the main
def main():
    log_file_name = "sample.log"
    output_file_name = "log_analysis_results.csv"

    # Performing the analysis
    ip_counts = count_requests_per_ip(log_file_name)
    most_accessed_endpoint = find_most_accessed_endpoint(log_file_name)
    suspicious_ips = detect_suspicious_activity(log_file_name, threshold=10)

    # Display results in the terminal
    print("Requests per IP:")
    for ip, count in ip_counts.items():
        print(f"{ip:<20}{count}")
    print()

    print("Most Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    print()

    print("Suspicious Activity Detected:")
    for ip, count in suspicious_ips.items():
        print(f"{ip:<20}{count}")
    print()

    # Saving the results to CSV
    write_results_to_csv(ip_counts, most_accessed_endpoint, suspicious_ips, output_file_name)
    print(f"Results saved to {output_file_name}")

# Run the main function
if __name__ == "__main__":
    main()
