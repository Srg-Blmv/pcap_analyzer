# 🛡 PCAP Analyzer 

### Анализ происходит через: 
- suricata
- zeek
- nDPI

### Карта на основе данных из лога:
- zeek conn.log


### Установка

```
apt install libpcap-dev tshark
```
``` 
cd pcap_analyzer
mkdir data
docker run -d --name suricata -v ./data:/tmp -v ./suricata_conf/:/home/suricata jasonish/suricata:7.0.11 suricata -c /home/suricata/suricata.yaml --unix-socket
docker pull zeek/zeek:8.0 

pip3 install -r requirements.txt
cd zeek_conf  && git clone https://github.com/CriticalPathSecurity/Zeek-Intelligence-Feeds
cd Zeek-Intelligence-Feeds && sed -i 's|/usr/local/zeek/share/zeek/site/|/opt/|g' main.zeek

streamlit run upload.py

# включаем наборы правил
docker exec suricata suricata-update enable-source et/open && \
docker exec suricata suricata-update enable-source abuse.ch/sslbl-ja3 && \
docker exec suricata suricata-update enable-source abuse.ch/sslbl-c2  && \
docker exec suricata suricata-update enable-source abuse.ch/feodotracker  && \
docker exec suricata suricata-update enable-source abuse.ch/urlhaus && \
docker exec suricata suricata-update enable-source etnetera/aggressive && \
docker exec suricata suricata-update enable-source pawpatrules && \
docker exec suricata suricata-update enable-source ptrules/open && \
docker exec suricata suricata-update enable-source stamus/lateral && \
docker exec suricata suricata-update enable-source aleksibovellan/nmap

docker exec suricata suricata-update 
```
Для загрузки файлова больше 210mb

``` 
python ./bigfile_upload.py  ./sample.pcap 
```


Добавил в nDPIreader протоколы:
1) Fanuc Focas2
2) LCV2

tshark на больших файлах очень медленно из за резолва mac
