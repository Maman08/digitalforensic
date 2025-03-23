import re
from typing import Optional,List
from fastapi import FastAPI,BackgroundTasks, HTTPException, requests
from fastapi.middleware.cors import CORSMiddleware
import socket
import time
import threading
from fastapi.responses import JSONResponse
from scapy.all import sniff,IP,TCP,UDP 
from scapy.interfaces import get_if_list
from pydantic import BaseModel
from collections import deque
import subprocess
import logging
from influxdb import InfluxDBClient
import requests

app=FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"], 
    allow_headers=["*"], 
)
PORT = 8004
INTERFACE=''

my_client=InfluxDBClient(host='localhost',port=8086)
my_client.switch_database('network_data')
def classify_alert(packet_info):
    """Classify the packet for potential security threats"""
    alert = None
    unusual_ports = [23, 445, 3389, 8080]  # Common attack ports
    external_ips = ["185.", "34.", "169."] 

    if packet_info["length"] > 1000:
        alert = "large_packet"
    elif packet_info["dest_port"] in unusual_ports:
        alert = "unusual_port"
    elif any(packet_info["dest_ip"].startswith(ip) for ip in external_ips):
        alert = "external_traffic"
    
    return alert or "normal"

def write_to_db(packet_info):
    json_body=[
        {
            "measurement":"packets",
            "tags":{
                "protocol":packet_info['protocol'],
                "source_ip":packet_info['source_ip'],
                "dest_ip":packet_info['dest_ip'],
                "alert": classify_alert(packet_info)
                
            },
            "fields": {
                "packet_size": packet_info["length"],
                "source_port": packet_info.get("source_port"),
                "dest_port": packet_info.get("dest_port"),
                
                
            }
        }
    ]
    my_client.write_points(json_body)
logging.basicConfig(level=logging.INFO)
logger=logging.getLogger(__name__)

class packetInfo(BaseModel):
    timestamp:float
    source_ip:Optional[str]=None
    dest_ip:Optional[str]=None
    source_host:Optional[str]=None
    dest_host:Optional[str]=None
    protocol:str
    length:int
    source_port:Optional[int]=None
    dest_port:Optional[int]=None

packet_buffer=deque(maxlen=1000)
capturing =False
capturing_thread=None

def process_packet(packet):
    packet_info={
        "timestamp":time.time(),
        "protocol":"OTHER",
        "length":len(packet),
    }
    if IP in packet:
        packet_info["source_ip"]=packet[IP].src
        packet_info["dest_ip"]=packet[IP].dst
        packet_info["source_host"]=get_hostname(packet[IP].src)
        packet_info["dest_host"]=get_hostname(packet[IP].dst)
        if TCP in packet:
            packet_info["protocol"] = "TCP"
            packet_info["source_port"] = packet[TCP].sport
            packet_info["dest_port"] = packet[TCP].dport
        elif UDP in packet:
            packet_info["protocol"] = "UDP"
            packet_info["source_port"] = packet[UDP].sport
            packet_info["dest_port"] = packet[UDP].dport
    write_to_db(packet_info)        
    packet_buffer.append(packetInfo(**packet_info))    

def capture_packet():
    global capturing
    while capturing:
        try:
            sniff(iface=INTERFACE,prn=process_packet,store=0,count=1,filter='ip')
        except Exception as e:
            print(f"capture errror :{e}")
            break


def get_hostname(ip:str)->str:
    try:
        host_name,_,_=socket.gethostbyaddr(ip)
        return host_name
    except socket.herror:
        return None    


@app.post("/capture/start")
async def start_capture():
    global capturing,capturing_thread

    if capturing:
        return JSONResponse(
            status_code=400,
            content={"message","Capture already running"}
        )
    capturing=True
    capturing_thread=threading.Thread(target=capture_packet)
    capturing_thread.start()
    return {"message": "Packet capture started"}


@app.get("/packets",response_model=List[packetInfo])
async def get_packets(limit:int =100):
    packet =list(packet_buffer)[-limit:]
    return packet

@app.post("/stop")
def stop_capturing():
    global capturing, capturing_thread

    if not capturing:
        return JSONResponse(
            status_code=400,
            content={"message":"No capture is running"}
        )
    capturing=False
    if capturing_thread:
        capturing_thread.join()
        capturing_thread=None
    return {"message": "Packet capture stopped"} 

class BlockRequest(BaseModel):
    ip: str

def get_mac_address(ip: str) -> str:
    try:
        # arp command mac address deta hai
        cmd = f"arp -n {ip}"
        # arp -n | grep 192.168.1.3
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        if result.returncode != 0:
            return None

        # Extract MAC address using regex
        match = re.search(r"([0-9A-Fa-f:]{17})", result.stdout)
        if match:
            return match.group(1)
        return None
    except Exception as e:
        return None

@app.post("/block")
def block_ip(request: BlockRequest):
    ip = request.ip

    
    if not ip.count('.') == 3:
        raise HTTPException(status_code=400, detail="Invalid IP address")

  
    mac = get_mac_address(ip)
    if not mac:
        raise HTTPException(status_code=404, detail=f"MAC address for {ip} not found")

    try:
        # Block the MAC address using ebtables
        cmd = f"ebtables -A INPUT -s {mac} -j DROP"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        if result.returncode == 0:
            return {"message": f"IP {ip} (MAC: {mac}) blocked successfully"}
        else:
            return {"error": result.stderr}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))







#webscan services

def run_nikto(url:str):
    result=subprocess.run(["sudo","nikto","-h",url],capture_output=True,text=True)
    # print(result.stdout)
    logger.info(result.stdout)
    return result.stdout

def run_nmap(url:str):
    result=subprocess.run(['sudo','nmap','-p','80,443',url],capture_output=True,text=True)
    # print(result.stdout)
    logger.info(result.stdout)
    return(result.stdout)

# run_nmap('http://bounty-birbal-ruby.vercel.app')

class ScanRequest(BaseModel):
    url: str   

scan_res={}
@app.post("/scan/")
async def scan(request: ScanRequest):
    try:
        url = request.url 
        scan_id = str(time.time())
        scan_res[scan_id] = {"status": "under progress"}

        nikto_result = run_nikto(url)
        nmap_result = run_nmap(url)

        scan_res[scan_id] = {
            "nikto_result": nikto_result,
            "nmap_result": nmap_result,
            "status": "completed",
        }
        return JSONResponse(content={"scan_id": scan_id})

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error during scan: {e}")



@app.get('/scan_status')
async def scan_status(scan_id:str):
    if scan_id in scan_res:
        return JSONResponse(content=scan_res[scan_id])
    else:
        return JSONResponse(content={"status":"id not found"}) 
    






def parse_pslist(output):
    # Removing ---> Volatility 3 Framework 2.22.0\n\n
    prefix_trim=output[31:]
    lines=prefix_trim.strip().split('\n')
    if not lines:
        return []
    headers = lines[0].split("\t")
    data=[]
    for line in lines:
        value=line.split('\t')
        row_dict=dict(zip(headers, value))
        data.append(row_dict)
        final=data[2:]
    return final    
    # print(prefix_trim)



memoryfile= "/home/mritunjay/memins/volatility3/memory.lime"
python_exect="/home/mritunjay/memins/volatility3/venv/bin/python"
vol_exec="/home/mritunjay/memins/volatility3/vol.py"
@app.get('/analyze/{command}')
async def analyze(command):
    result=subprocess.run([python_exect,vol_exec,"-f",memoryfile, f"linux.{command}" ],capture_output=True, text=True)
    # return {"output":result.stdout}
    data=parse_pslist(result.stdout)
    return {"data":data}







trusted_ips = ["192.168.45.57", "163.70.139.60"]

# Global list to store detected SSH connections
# Mar 23 14:33:15 server sshd[12347]: Failed password for root from 203.0.113.45 port 37219 ssh2
# ["Mar 23 14:33:15 server sshd[12347]: Failed password for root", "203.0.113.45 port 37219 ssh2"]
# 203.0.113.45
# sudo tail -n 20 /var/log/auth.log



ssh_connections = deque(maxlen=100)
ssh_connections_lock = threading.Lock()

def analyze_ssh_logs(log_file="/var/log/auth.log"):
    suspicious_ips = set()
    brute_force_attempts = {}

    try:
        with open(log_file, "r") as f:
            for line in f:
                try:
                    if "Failed password" in line:
                        ip = line.split("from ")[1].split(" ")[0]
                        brute_force_attempts[ip] = brute_force_attempts.get(ip, 0) + 1
                    if "Accepted password" in line:
                        ip = line.split("from ")[1].split(" ")[0]
                        if ip not in trusted_ips:
                            suspicious_ips.add(ip)
                except IndexError:
                    continue  # Skip malformed lines
    except FileNotFoundError:
        return {"error": "Log file not found"}
    except Exception as e:
        return {"error": str(e)}

    return {
        "suspicious_ips": list(suspicious_ips),
        "brute_force_attempts": brute_force_attempts
    }

@app.get("/detect-ssh-attacks")
async def detect_ssh_attacks():
    result = analyze_ssh_logs()
    return {"ssh_attack_detection": result}

def detect_ssh_traffic(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP) and packet[TCP].dport == 22:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        connection = {"src_ip": src_ip, "dst_ip": dst_ip}
        with ssh_connections_lock:
            ssh_connections.append(connection)
        print(f"SSH connection detected from {src_ip} to {dst_ip}")

def start_ssh_monitoring():
    available_interfaces = get_if_list()
    if not available_interfaces:
        print("No network interfaces found!")
        return

    interface = available_interfaces[0]
    print(f"Starting SSH traffic monitoring on interface: {interface}")
    sniff(iface=interface, prn=detect_ssh_traffic, filter="tcp port 22", count=0)

# Start SSH monitoring in a separate thread
monitoring_thread = threading.Thread(target=start_ssh_monitoring)
monitoring_thread.daemon = True
monitoring_thread.start()

@app.get("/ssh-connections")
async def get_ssh_connections():
    with ssh_connections_lock:
        return {"ssh_connections": list(ssh_connections)}
    









# yara 


MEMORY_LIME_PATH = "/home/mritunjay/memins/volatility3/memory.lime"

YARA_RULES_PATH = "/home/mritunjay/rules/combined_rules.yar"


@app.post("/yarascan/")
async def scan_file():
    try:
        result = subprocess.run(
            ["yara", YARA_RULES_PATH, MEMORY_LIME_PATH],
            capture_output=True,
            text=True,
        )
        yara_output = result.stdout
    except Exception as e:
        return {"error": f"YARA error: {e}"}

    matches = yara_output.strip().split("\n")


    return {
        "yara_matches": matches,
    }


@app.get("/")
def hello():
    return{"message":"hello "}



if __name__=="__main__":
    import uvicorn
    uvicorn.run(app,host="0.0.0.0",port=PORT)



# # host_name = socket.gethostbyaddr("8.8.8.8")
# # # print(host_name)
# Yes, when you use Yes, when you use the sniff() function with the prn=process_packet argument, Scapy automatically passes each captured packet to the process_packet function as an input.the sniff() function with the prn=process_packet argument, Scapy automatically passes each captured packet to the process_packet function as an input.



# import subprocess

# subprocess.run(['sudo', 'nmap', '-sn', '192.168.1.0/24'])

# The ** operator unpacks the dictionary, passing its keys as argument names and values as their respective values to the packetInfo constructor.
# packetInfo(key1=value1, key2=value2, ...)

# sniff(ifcae=interface_name,prn=function_to_process_that packet,store=0 iska mtlb dont store it in RAM , count=1 iska mtlb catch one packet only at a time ,filter='ip')

# sudo $(which python3) main.py
