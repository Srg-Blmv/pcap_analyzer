# 🛡 PCAP Analyzer 

### Network dump analysis using: 
- suricata
- zeek
- nDPI

``` 
cd pcap_analyzer
docker run -d  --name suricata -v ./data:/tmp  -v ./suricata_conf/:/home/suricata  jasonish/suricata:7.0.11 suricata -c /home/suricata/conf/suricata.yaml -s /home/suricata/rules/ --unix-socket
docker pull zeek/zeek:8.0 
mkdir data
pip3 install -r requirements.txt
streamlit run upload.py
```
Use only lowercase letters, numbers, underscores, hyphens and one dot before extension — no spaces or special characters (!@#$%^&*()+=[]{}|;:'",<>?/~)
