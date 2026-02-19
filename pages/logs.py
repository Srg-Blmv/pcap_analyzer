import pandas as pd
import streamlit as st
import json
import os
from pathlib import Path


LOG_DIR = Path("data")
#st.set_page_config(layout="wide")


# uploaded_file = st.file_uploader("Choose a file")
# if uploaded_file is not None:
#   df = pd.read_csv(uploaded_file)
#   st.write(dataframe)


# Читаем eve.json построчно
#ata = []
#with open(
#    "/home/sb/Документы/new_pcap_analizer/2026-02-18_19-10-49_attack_malware_release_5.0/suricata/eve.json"
#) as f:
#    for line in f:
#        data.append(json.loads(line))



folder = os.listdir(LOG_DIR)
print(folder)


# # Превращаем в DataFrame
# df = pd.json_normalize(data)  # нормализует вложенные поля
# df_alert = df[df["event_type"] == "alert"][
#     [
#         "timestamp",
#         "src_ip",
#         "src_port",
#         "dest_ip",
#         "dest_port",
#         "proto",
#         "app_proto",
#         "alert.signature",
#         "alert.category",
#         "alert.severity",
#         "alert.signature_id",
#         "payload",
#     ]
# ].reset_index(drop=True)


# st.text("Suricata")
# with st.expander("Все события", expanded=False):
#     st.dataframe(df, height=700)


# with st.expander("Только Алерты", expanded=False):
#     st.dataframe(
#         df_alert,
#         height=700,
#     )

# st.text("Zeek")
# folder = Path("/home/sb/Документы/new_pcap_analizer/2026-02-18_19-10-49_attack_malware_release_5.0/zeek/")

# for file in folder.iterdir():
#     if file.is_file():
#         data = []
#         with open(file) as f:
#             for line in f:
#                 data.append(json.loads(line))

#         df = pd.json_normalize(data)

#         with st.expander(f"{file.name} ({len(df)})", expanded=False):
#             st.dataframe(df, use_container_width=True, height=700)