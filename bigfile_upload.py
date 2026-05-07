import os
from pathlib import Path
from datetime import datetime
import argparse
import shutil


LOG_DIR = Path("data")

parser = argparse.ArgumentParser()
parser.add_argument('pcap', type=str, help='path to pcap')
args = parser.parse_args()



path_pcap = Path(args.pcap)

print(path_pcap)

if path_pcap:


    file_name = path_pcap.name
    name_pcap_dir = f'{datetime.now().strftime("%Y-%m-%d")}_{Path(file_name).stem}'
    path_dir = f'{LOG_DIR}/{name_pcap_dir}'
    full_path_file = f'{path_dir}/{file_name}'
    os.mkdir(path_dir)

    shutil.copy2(path_pcap, full_path_file)
    print(f"copy pcap: {full_path_file}")

    # suricata
    os.mkdir(f'{path_dir}/suricata')
    os.system(f"docker exec  suricata  suricatasc -c  'pcap-file /tmp/{name_pcap_dir}/{file_name} /tmp/{name_pcap_dir}/suricata/'   /var/run/suricata/suricata-command.socket")
        
    # zeek
    os.mkdir(f'{path_dir}/zeek')
    os.system(
        #f'docker run --rm -v {os.path.abspath("data")}:/pcap  -v {os.path.abspath("zeek_conf")}:/opt   zeek/zeek:8.0  bash -c "cd /pcap/{name_pcap_dir}/zeek && zeek -C -r ../{file_name}  /opt/Zeek-Intelligence-Feeds/__load__.zeek  LogAscii::use_json=T"')
        f'docker run --rm -v {os.path.abspath("data")}:/pcap  -v {os.path.abspath("zeek_conf")}:/opt   zeek/zeek:8.0  bash -c "cd /pcap/{name_pcap_dir}/zeek && zeek -C -r ../{file_name}  /opt/conf.zeek  LogAscii::use_json=T"')


    # ndpi
    os.mkdir(f'{path_dir}/ndpi')
    os.system(
        f'{os.path.abspath("ndpi")}/ndpiReader -i {full_path_file} -d -F -t -K json -k {path_dir}/ndpi/ndpi.json > {path_dir}/ndpi/ndpi_summary.log 2>&1')

