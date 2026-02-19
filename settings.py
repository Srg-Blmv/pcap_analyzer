import pandas as pd
import streamlit as st
import json
import os
from pathlib import Path
from datetime import datetime
import time

LOG_DIR = Path("data")

st.set_page_config(layout="wide")

if st.button("clean data"):
    os.system(f"rm -rf {LOG_DIR}/*")
    st.success('data cleaned')

uploaded_file = st.file_uploader(
    "Choose a file", type=["pcapng", "pcap"], max_upload_size=10)

if uploaded_file is not None:
    try:
        file_name = uploaded_file.name
        name_pcap_dir = f'{datetime.now().strftime("%Y-%m-%d")}_{Path(file_name).stem}'
        path_dir = f'{LOG_DIR}/{name_pcap_dir}'
        full_path_file = f'{path_dir}/{file_name}'
        os.mkdir(path_dir)

        with open(full_path_file, "wb") as f:
            f.write(uploaded_file.getvalue())
        st.success('file save')
        
        # suricata
        os.mkdir(f'{path_dir}/suricata')
        with st.spinner("Suricata run, Wait for it...", show_time=True):
            os.system(f"docker run  --rm -v {os.path.abspath('data')}:/tmp  -v {os.path.abspath('suricata_conf')}:/home/suricata jasonish/suricata:7.0.11 \
                suricata -c /home/suricata/conf/suricata.yaml -s /home/suricata/rules/ -k none -r /tmp/{name_pcap_dir}/{file_name} --runmode=autofp -l /tmp/{name_pcap_dir}/suricata/ ")
        st.success('suricata done')

        # zeek
        os.mkdir(f'{path_dir}/zeek')
        with st.spinner("Zeek run, Wait for it...", show_time=True):
            os.system(
                f'docker run --rm -v {os.path.abspath("data")}:/pcap zeek/zeek:8.0 bash -c "cd /pcap/{name_pcap_dir}/zeek && zeek -C -r ../{file_name} LogAscii::use_json=T"')
        st.success('zeek done')

        
        # ndpi
        os.mkdir(f'{path_dir}/ndpi')
        with st.spinner("nDPI run, Wait for it...", show_time=True):
            os.system(
                f'{os.path.abspath("ndpi")}/ndpiReader -i {full_path_file} -d -F -t -K json -k {path_dir}/ndpi/ndpi.json > {path_dir}/ndpi/ndpi_summary.log 2>&1')
        st.success('ndpi done')
        
        
    except FileExistsError:
        st.error('file already exists')
