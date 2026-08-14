import pandas as pd
import streamlit as st
import graphviz
import os
from pathlib import Path
import json
from pyvis.network import Network

LOG_DIR = Path("data")
folder = os.listdir(LOG_DIR)

st.set_page_config(layout="wide")
st.subheader(f"Network map pcap: {st.session_state.key}")
st.html("<hr></hr>")
# static Graf


def graf(connections, name):
    dot = graphviz.Digraph()
    dot.attr(label=name, labelloc='t', rankdir='LR',  rank='same')
    for _, row in connections.iterrows():
        if len(row['id.resp_p']) > 3:
            port = (
                f"{row['id.resp_p'][:3]} + {len(row['id.resp_p'])-3} more").replace("[", "").replace("]", "")
        else:
            port = str(row['id.resp_p']).replace("[", "").replace("]", "")
        dot.edge(
            row['id.orig_h'],
            row['id.resp_h'],
            title=f"port: {port}",
            label=str(port)
        )

    return dot


# dinamic Graf
def dinamic_graf():
    net_tcp = Network(directed=True, neighborhood_highlight=True,
                      height="1000px", width="100%")

    net_udp = Network(directed=True, neighborhood_highlight=True)

#     options = {
#         "layout": {
#             "hierarchical": {
#                 "enabled": True,
#                 "direction": "UD",
#                 "sortMethod": "directed",  # СМЕНИТЕ на "hubsize" — группирует хабы, сокращает treeSpacing в широких графах
#                 "levelSeparation": 80,
#                 "nodeSpacing": 170,
#                 "treeSpacing": 140,
#                 "blockShifting": True,       # ✅ Сдвигает блоки узлов для коротких рёбер
#                 "edgeMinimization": True,    # ✅ Минимизирует длины рёбер математически
#                 "parentCentralization": True, # ✅ Централизует детей к родителям
#                 "shakeTowards": "leaves"  #  Встряхивает листья вверх, сжимая дерево
#             }
#         },
#         "edges": {
#             "length": 150,           # Фиксированная длина рёбер
#             "smooth": True
#         },
#         "nodes": {
#             "shape": "dot",
#             "size": 12,  # Уменьшаем размер узлов
#             "font": {"size": 10}  # Уменьшаем шрифт
#         },
#         "physics": {
#             "enabled": False  # Отключаем физику для стабильного иерархического вида
#         }
#     }
    options = {
        "nodes": {"shape": "dot", "size": 18, "font": {"size": 14}},
        "edges": {"font": {"size": 14}, "length": 400},
        "interaction": {"dragNodes": True},
        "physics": {"enabled": False}
        # "physics": {
        #     "barnesHut": {
        #         "theta": 0.55,
        #         "gravitationalConstant": -35100,
        #         "centralGravity": 0,
        #         "springLength": 0,
        #         "damping": 1
        #     },
        #     "maxVelocity": 125,
        #     "minVelocity": 0.75,
        #     "timestep": 1,
        #     "wind": {
        #         "y": 0.4
        #     }
        # },
        # "configure": {
        #     "enabled": True,
        #     #            "filter": ["physics"]
        # }
    }

    net_tcp.set_options(json.dumps(options))
    net_udp.set_options(json.dumps(options))

    all_ips_tcp = set(gr_tcp['id.orig_h']).union(set(gr_tcp['id.resp_h']))
    all_ips_udp = set(gr_udp['id.orig_h']).union(set(gr_udp['id.resp_h']))

    for ip in all_ips_tcp:
        net_tcp.add_node(ip, label=ip, shape="circle")

    for ip in all_ips_udp:
        net_udp.add_node(ip, label=ip, shape="circle")

    for _, row in gr_tcp.iterrows():
        if len(row['id.resp_p']) > 3:
            port = (
                f"{row['id.resp_p'][:3]} + {len(row['id.resp_p'])-3} more").replace("[", "").replace("]", "")
        else:
            port = str(row['id.resp_p']).replace("[", "").replace("]", "")

        net_tcp.add_edge(
            row['id.orig_h'],
            row['id.resp_h'],
            title=f"port: {port}",
            smooth={"type": "continuous"},  # , "roundness": 0.1},
            label=str(port),
        )

    for _, row in gr_udp.iterrows():
        if len(row['id.resp_p']) > 3:
            port = (
                f"{row['id.resp_p'][:3]} + {len(row['id.resp_p'])-3} more").replace("[", "").replace("]", "")
        else:
            port = str(row['id.resp_p']).replace("[", "").replace("]", "")

        net_udp.add_edge(
            row['id.orig_h'],
            row['id.resp_h'],
            title=f"port: {port}",
            smooth={"type": "continuous"},  # , "roundness": 0.1},
            label=str(port),
        )
    net_tcp.write_html('net_tcp_work.html')
    net_udp.write_html('net_udp_work.html')

    HtmlFile_tcp = open("net_tcp_work.html", "r", encoding="utf-8")
    HtmlFile_udp = open("net_udp_work.html", "r", encoding="utf-8")
    st.header("TCP")
    st.html("<hr></hr>")
    # , scrolling=False)
    st.components.v1.html(HtmlFile_tcp.read(), height=700)
    st.header("UDP")
    st.html("<hr></hr>")
    # , scrolling=False)
    st.components.v1.html(HtmlFile_udp.read(), height=700)



if 'key' not in st.session_state:
    st.session_state.key = None
def change_folden():
    st.session_state.key =  st.session_state.new_folden

select_folder = st.session_state.key
st.selectbox("select folder", folder, on_change=change_folden, key='new_folden', index=None, placeholder="Выберети папку")

st.set_page_config(layout="wide")

static_graf = st.checkbox("Static Graf", value=True)
st.caption("A static graph may not work well with a large number of hosts.")

if select_folder != None:
    zeek_con = Path(f'{LOG_DIR}/{select_folder}/zeek/conn.log')

    data = []
    with open(zeek_con) as f:
        for line in f:
            data.append(json.loads(line))

        df = pd.json_normalize(data)
        uniq_conn = df[["id.orig_h", "id.resp_h",
                        "id.resp_p", "proto"]].drop_duplicates()
        only_ipv4 = uniq_conn[
            uniq_conn["id.orig_h"].str.contains(r'\.', na=False) &
            uniq_conn["id.resp_h"].str.contains(r'\.', na=False)
        ]

        only_tcp = only_ipv4.loc[uniq_conn["proto"] == 'tcp']
        only_udp = only_ipv4.loc[uniq_conn["proto"] == 'udp']

        gr_tcp = only_tcp.groupby(['id.orig_h', 'id.resp_h']).agg(
            {'id.resp_p': list}).reset_index()

        gr_udp = only_udp.groupby(['id.orig_h', 'id.resp_h']).agg(
            {'id.resp_p': list}).reset_index()


    if static_graf:

        dot_tcp = graf(gr_tcp, "IPv4 TCP")
        dot_udp = graf(gr_udp, "IPv4 UDP")
        st.header("TCP")
        st.html("<hr></hr>")
        st.graphviz_chart(dot_tcp)

        st.header("UDP")
        st.html("<hr></hr>")
        st.graphviz_chart(dot_udp)

    else:
        dinamic_graf()
