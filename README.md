Project Overview
This repository showcases a hands-on SOC (Security Operations Center) analysis conducted during a cybersecurity internship, leveraging the Elastic Stack (Kibana, Elasticsearch, Logstash) and Kali Linux.
The project focuses on threat detection, incident response, and remediation strategies, with each security event mapped to the OWASP Top 10 vulnerabilities.
Through this project, real-world attack simulations were analyzed to strengthen proactive defense mechanisms and enhance log visibility in enterprise environments.
________________________________________
 Tools & Technologies
•	Elastic Stack (Elasticsearch, Logstash, Kibana) – For centralized logging, visualization, and analytics
•	Kali Linux – For security testing and generating simulated attacks
•	Sample Log Files – For threat investigation and pattern analysis
•	MS Word – For professional reporting and documentation
________________________________________
Key Highlights
•	Real-Time Log Analysis: Investigated network and system logs through Kibana Discover dashboards
•	Threat Detection: Identified malware infections (Trojan, Rootkit) through abnormal log behaviors
•	Brute-Force & Login Failure Analysis: Tracked unauthorized login attempts to detect brute-force attacks
•	Connection Attempt Monitoring: Analyzed suspicious IP connections and potential lateral movement
•	 Alert Severity Classification: Categorized alerts based on impact and threat level for effective incident prioritization

Incident Timeline
 
Recommendations
To ensure effective containment and recovery, the following security countermeasures were implemented:
•	 Isolate Infected Hosts: Immediately disconnect compromised systems from the network to prevent lateral spread.
•	 Initiate Endpoint Malware Scans: Perform deep scans using updated antivirus and EDR tools to eliminate malicious files.
•	 Audit User Credentials: Review authentication logs and enforce password resets for affected or suspicious accounts.
•	 Monitor Flagged IP Ranges: Continuously track and block malicious IPs to prevent recurring intrusion attempts.
________________________________________
Notification & Escalation Plan
A structured incident communication workflow was followed to maintain clarity and speed in response:
•	 Alert SOC Lead: Automated alerts triggered to notify the SOC Lead in real-time.
•	 Report to IT Security Manager: Comprehensive incident summary shared with analysis findings and next-step recommendations.
•	Prepare Containment Instructions: Action plan distributed to system admins for immediate remediation and future prevention.
________________________________________
 Dashboard Insights & Visualizations
Key Kibana dashboards were created to enhance situational awareness and visualize threat patterns:
•	 Filtered Threats & Actions: Interactive view of detected anomalies and response actions taken.
•	 Alert Visualizations: Graphical representation of incident trends, login failures, and malware detections.
•	Severity Breakdown: Categorization of alerts into Low, Medium, High, and Critical impact levels for better prioritization.
 

