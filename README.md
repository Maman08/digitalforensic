*Project Report: Digital Forensics Tool*

### *1. Introduction*
Digital forensic investigations require efficient tools to analyze evidence quickly and accurately. This project aims to develop a *Cyber Triage & Digital Forensics Tool* that automates forensic analysis, threat detection, and report generation. The tool will assist investigators in processing forensic disk images, network packets, integrating ML for anomaly detection.

### *2. Objectives*
- *Automate forensic data collection* from RAW images, memory dumps, and network traffic.
- *Detect Indicators of Compromise (IOCs)* using ML-powered anomaly detection.
- *Enable real-time packet analysis* for identifying suspicious network activities.
- *Real-time monitoring* with GRAFANA 
- *SSH Lateral entry attack* detection


### *3. System Architecture*
#### *3.1 Tech Stack*
- *Frontend:* React.js (Forensic Dashboard)
- *Backend:* FastAPI (Python-based API)
- *Forensic Tools:* Volatility, Scapy ,YARA
- *AI/ML:* TensorFlow, Scikit-Learn
- *Reporting:* GRAFANA

#### *3.2 Key Modules*
1. *Disk & Memory Forensics*
   - Extract system logs, registry entries, running processes.
   - Recover deleted files and detect malware using YARA rules.

2. *Network Traffic Analysis*
   - Capture and analyze live network packets.
   - Detect unauthorized access and suspicious connections.

3. *AI-Based Threat Detection*
   - Train AI models for pattern recognition and anomaly detection.
   - Implement risk scoring to prioritize forensic findings.

4. *Interactive Dashboard & Reporting*
   - Visualize forensic timelines and threat analysis.
   - Generate automated investigation reports.

5. *SSH lateral entry attack*
   - Get all the SSH connections
   - Get the suspecious IP that failing to ssh frequently



