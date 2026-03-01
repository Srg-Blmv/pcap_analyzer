import pandas as pd
import streamlit as st
import graphviz
import os
from pathlib import Path
from scapy.all import *


LOG_DIR = Path("data")
folder = os.listdir(LOG_DIR)



def graf(connections, name):
    dot = graphviz.Digraph()
    dot.attr(label=name,labelloc='t')
    for (src, dst), port  in connections.items():

        if len(port) > 3:
            port =  sorted(port)
            three_ports = str(list(port)[:3]).replace("[","").replace("]","")
            dot.edge(str(src), str(dst) , label=f"{three_ports} + {len(port)-3} more")
        else:
            port = str(port).replace("{","").replace("}","")
            dot.edge(str(src), str(dst) , label=f"{port}")

    return dot



select_folder = st.selectbox("select folder", folder)
st.set_page_config(layout="wide")


if select_folder != None:
    path_to_work_folder = Path(f'{LOG_DIR}/{select_folder}')

    path_pcap_file = list(path_to_work_folder.glob("*.pcap")) or list(path_to_work_folder.glob("*.pcapng"))


    with st.spinner("Analysis pcap", show_time=True):
    

        with PcapReader(str(path_pcap_file[0])) as pcap_reader:
            connections_tcp = {}
            connections_udp = {}

            for pkt in pcap_reader:
                if IP in pkt:
                    l3 = pkt[IP]

                    if TCP in pkt:
                        l4 = pkt[TCP]
                        if l4.flags == "S": 
                            key = (l3.src, l3.dst)
                            if key not in connections_tcp:
                                connections_tcp[key] = set()
                            
                            connections_tcp[key].add(l4.dport)

                    elif UDP in pkt:
                        l4 = pkt[UDP]
                        key = (l3.src, l3.dst)

                        if key not in connections_udp:
                            connections_udp[key] = set()
                            
                        connections_udp[key].add(l4.dport)
    st.toast('Analysis pcap done')               

    dot_tcp = graf(connections_tcp, "IPv4 TCP")
    dot_udp = graf(connections_udp, "IPv4 UDP")

    st.graphviz_chart(dot_tcp)
    st.graphviz_chart(dot_udp)


else:
    pass



