# -Log-Analysis-Script

# Purpose:
A Python script for analyzing server log files to provide insights such as request counts, most accessed endpoints, and failed login attempts. Designed to assist system administrators in monitoring server activity effectively.

# Key Features:

1. Identifies and counts all requests grouped by IP address.
2. Tracks and summarizes failed login attempts by IP.
3. Lists the most frequently accessed endpoints.

# Technologies Used:
Python 3, re (Regular Expressions), collections (defaultdict).

How to Use:

1. Place your log file (sample.log) in the same directory as the script.
2. Run the script: python log_analysis.py.
3. View the generated output on the console.
