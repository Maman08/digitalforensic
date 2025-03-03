export interface ScanResponse {
  scan_id: string;
  status: string;
}

export interface VulnerabilityData {
  "Found Errors": string[];
  "Vulnerability Severity": {
    Critical: number;
    High: number;
    Medium: number;
    Low: number;
  };
}

export interface ScanResult {
  "Target IP": string;
  "Target Hostname": string;
  "Target Port": string;
  "Server": string;
  "Scan Start Time": string;
  "Scan End Time": string;
  "Scan Duration": string;
  "Vulnerability Data": VulnerabilityData;
}

export interface ScanError {
  message: string;
}