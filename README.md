# Log-Analysis-Script
This Python script analyzes web server log files to extract and analyze key information, helping you monitor activity and detect potential security threats.

## Features

### Count Requests per IP Address:
- Extracts all IP addresses from the log file.
- Counts the number of requests made by each IP.
- Displays the results sorted by the number of requests in descending order.

### Identify the Most Frequently Accessed Endpoint:
- Finds the endpoint (e.g., /home, /login) accessed the most times.
- Displays the endpoint and the number of times it was accessed.

### Detect Suspicious Activity:
- Identifies IPs with excessive failed login attempts (default threshold: 10 attempts).
- Flags these IPs as potential brute force attacks.
- Displays flagged IP addresses and the number of failed login attempts.

### Output Results:
- Results are displayed in the terminal in a readable format.
- Saves the analysis to a CSV file (`log_analysis_results.csv`) with three sections:
  - Requests per IP
  - Most Accessed Endpoint
  - Suspicious Activity
