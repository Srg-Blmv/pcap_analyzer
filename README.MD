# 🛡 PCAP Analyzer 

### Network dump analysis using: 
- suricata
- zeek
- nDPI

### Network Map Visualizer
- TCP connections: Only packets with SYN flags are considered (connection initiation)
- UDP connections: All UDP traffic is mappe


### Installation

``` 
cd pcap_analyzer
mkdir data
docker run -d --name suricata -v ./data:/tmp -v ./suricata_conf/:/home/suricata jasonish/suricata:7.0.11 suricata -c /home/suricata/conf/suricata.yaml --unix-socket
docker pull zeek/zeek:8.0 
pip3 install -r requirements.txt
streamlit run upload.py

# enable source rules
docker exec suricata suricata-update enable-source et/open && \
docker exec suricata suricata-update enable-source abuse.ch/sslbl-ja3 && \
docker exec suricata suricata-update enable-source stamus/lateral && \
docker exec suricata suricata-update enable-source abuse.ch/feodotracker && \
docker exec suricata suricata-update enable-source abuse.ch/urlhaus && \
docker exec suricata suricata-update enable-source oisf/trafficid && \
docker exec suricata suricata-update enable-source aleksibovellan/nmap

docker exec suricata suricata-update 
```
Use only lowercase letters, numbers, underscores, hyphens and one dot before extension — no spaces or special characters (!@#$%^&*()+=[]{}|;:'",<>?/~)



