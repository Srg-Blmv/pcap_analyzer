# 🛡 PCAP Analyzer 

### Анализ происходит через: 
- suricata
- zeek
- nDPI

### Карта на основе данных из лога:
- zeek conn.log


### Установка

```
для ndpi нужена библиотека
apt install libpcap-dev
```
``` 
cd pcap_analyzer
mkdir data
docker run -d --name suricata -v ./data:/tmp -v ./suricata_conf/:/home/suricata jasonish/suricata:7.0.11 suricata -c /home/suricata/suricata.yaml --unix-socket
docker pull zeek/zeek:8.0 
docker model pull ai/gemma3:4B-Q4_K_M
pip3 install -r requirements.txt
cd zeek_conf  && git clone https://github.com/CriticalPathSecurity/Zeek-Intelligence-Feeds
cd Zeek-Intelligence-Feeds && sed -i 's|/usr/local/zeek/share/zeek/site/|/opt/|g' main.zeek

streamlit run upload.py

# включаем наборы правил
docker exec suricata suricata-update enable-source et/open && \
docker exec suricata suricata-update enable-source abuse.ch/sslbl-ja3 && \
docker exec suricata suricata-update enable-source stamus/lateral && \
docker exec suricata suricata-update enable-source abuse.ch/feodotracker && \
docker exec suricata suricata-update enable-source abuse.ch/urlhaus && \
docker exec suricata suricata-update enable-source oisf/trafficid && \
docker exec suricata suricata-update enable-source aleksibovellan/nmap

docker exec suricata suricata-update 
```
Для загрузки файлова больше 250mb

``` 
python ./bigfile_upload.py  ./sample.pcap 
```




