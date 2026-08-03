import pandas as pd
import streamlit as st
import json
import os
from pathlib import Path
import geoip2.database
import ipaddress
import re
from streamlit_echarts import st_echarts
import plotly.express as px
import subprocess


LOG_DIR = Path("data")
folder = os.listdir(LOG_DIR)


# ========= MAIN ===============
if 'key' not in st.session_state:
    st.session_state.key = None

def change_folden():
    st.session_state.key =  st.session_state.new_folden

select_folder = st.session_state.key
st.selectbox("select folder", folder, on_change=change_folden, key='new_folden', index=None, placeholder="Выберети папку")

st.set_page_config(layout="wide")


def get_ip_dialog(folder):
    # tshark ipv4 dialog

    ipv4_dialog =  Path(f"{folder}/ipv4_dialog.csv")
    if ipv4_dialog.is_file():
        df = pd.read_csv(ipv4_dialog, names=['src.ip', 'src.mac', 'src.vendor', 'dst.ip', 'dst.mac', 'dst.vendor'])
        # Сортируем по src.ip
        df = df.sort_values(by=df.columns[0])
        # в колонке вендлора оставляем только название по умолнича там VMware_ab:a5:72
        df.iloc[:, 2] = df.iloc[:, 2].str.split('_').str[0]
        df.iloc[:, 5] = df.iloc[:, 5].str.split('_').str[0]

        #  src.ip, src.mac, src.vendor
        unique_src = df[['src.ip', 'src.mac', 'src.vendor']].drop_duplicates()

        #  dst.ip, dst.mac, dst.vendor
        unique_dst = df[['dst.ip', 'dst.mac', 'dst.vendor']].drop_duplicates()

        # Переименовываем колонки для объединения
        unique_src.columns = ['ip', 'mac', 'vendor']
        unique_dst.columns = ['ip', 'mac', 'vendor']

        # Объединяем src и dst в один DataFrame
        unique_all = pd.concat([unique_src, unique_dst], ignore_index=True)

        # Удаляем дубликаты по всем трем колонкам (ip + mac + vendor)
        unique_all = unique_all.drop_duplicates()

        # Сортируем по ip
        unique_all = unique_all.sort_values(by='ip').reset_index(drop=True)

        # Объединяем обе колонки в одну
        uniq_vendor = pd.concat([df['src.vendor'], df['dst.vendor']], ignore_index=True)
        # Удаляем дубликаты
        uniq_vendor = uniq_vendor.drop_duplicates().reset_index(drop=True)
    else:
        unique_all = None
        uniq_vendor = None
    return unique_all, uniq_vendor



if select_folder != None:
    # get data zeek
    folder_tshark = Path(f"{LOG_DIR}/{select_folder}/tshark/")

    st.subheader(f"Endpoints: {st.session_state.key}")
    st.html("<hr></hr>")
    #col1, col2, = st.columns(2, border=True)


    ipv4_dialog, uniq_vendor= get_ip_dialog(folder_tshark)
    if ipv4_dialog is not None and uniq_vendor is not None:
        st.badge(f"ip + mac  : {len(ipv4_dialog)}")
        st.dataframe(ipv4_dialog)
        st.badge(f"uniq mac vendor : {len(uniq_vendor)}")
        st.dataframe(uniq_vendor)
