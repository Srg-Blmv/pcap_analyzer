import pandas as pd
import streamlit as st
import graphviz
import os
from pathlib import Path
import json


LOG_DIR = Path("data")
folder = os.listdir(LOG_DIR)



def graf(connections, name):
    dot = graphviz.Digraph()
    dot.attr(label=name,labelloc='t', rankdir='TB',  rank='same')
    for _, row in connections.iterrows():
        if len(row['id.resp_p']) > 3:
            port = (f"{row['id.resp_p'][:3]} + {len(row['id.resp_p'])-3} more").replace("[","").replace("]","")
        else:
            port = str(row['id.resp_p']).replace("[","").replace("]","")
        dot.edge(
            row['id.orig_h'],
            row['id.resp_h'],
            title=f"port: {port}",
            label=str(port)
    )

    return dot



select_folder = st.selectbox("select folder", folder)
st.set_page_config(layout="wide")


if select_folder != None:
    zeek_con = Path(f'{LOG_DIR}/{select_folder}/zeek/conn.log')

    data = []
    with open(zeek_con) as f:
        for line in f:
            data.append(json.loads(line))

        df = pd.json_normalize(data)
        uniq_conn = df[["id.orig_h", "id.resp_h","id.resp_p","proto"]].drop_duplicates()
        only_ipv4 = uniq_conn[
            uniq_conn["id.orig_h"].str.contains(r'\.', na=False) & 
            uniq_conn["id.resp_h"].str.contains(r'\.', na=False)
        ]


        only_tcp = only_ipv4.loc[uniq_conn["proto"] == 'tcp']
        only_udp = only_ipv4.loc[uniq_conn["proto"] == 'udp']


        gr_tcp = only_tcp.groupby(['id.orig_h', 'id.resp_h']).agg({'id.resp_p':list }).reset_index()
        gr_udp = only_udp.groupby(['id.orig_h', 'id.resp_h']).agg({'id.resp_p':list }).reset_index()



    dot_tcp = graf(gr_tcp, "IPv4 TCP")
    dot_udp = graf(gr_udp, "IPv4 UDP")

    st.graphviz_chart(dot_tcp)
    st.graphviz_chart(dot_udp)


else:
    pass



