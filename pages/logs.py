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

LOG_DIR = Path("data")
folder = os.listdir(LOG_DIR)





def suricata(file):
    # Читаем eve.json построчно
    data = []
    df_alert = []
    severity_counts = []

    with open(file) as f:
        for line in f:
            data.append(json.loads(line))

    # # Превращаем в DataFrame
    df = pd.json_normalize(data)  # нормализует вложенные поля
    df_alert = df[df["event_type"] == "alert"].copy()

    cols = [
        "timestamp",
        "src_ip",
        "src_port",
        "dest_ip",
        "dest_port",
        "proto",
        "app_proto",
        "alert.signature",
        "alert.category",
        "alert.severity",
        "alert.signature_id",
        "payload",
    ]
    # Если в сурикате нет такой создатим и напишем пустое значение
    for c in cols:
        if c not in df_alert.columns:
            df_alert[c] = ""

    df_alert = df_alert[cols].reset_index(drop=True)

    # Количество алертов в зависимости от критичности
    severity_counts = df_alert["alert.severity"].value_counts().sort_index()

    return df, df_alert, severity_counts


def zeek(folder):
    # ZEEK
    result = []
    for file in folder.iterdir():
        if file.is_file():
            data = []
            with open(file) as f:
                for line in f:
                    data.append(json.loads(line))
            df = pd.json_normalize(data)

            result.append({"file_name": file.name, "df": df})
    return result



def ndpi(file):

    with open(file, 'r', encoding='utf-8') as f:
        content = f.read()
    return content



if 'key' not in st.session_state:
    st.session_state.key = None
def change_folden():
    st.session_state.key =  st.session_state.new_folden

select_folder = st.session_state.key
st.selectbox("select folder", folder, on_change=change_folden, key='new_folden', index=None, placeholder="Выберети папку")

st.set_page_config(layout="wide")


if select_folder != None:

    # get data zeek
    folder_zeek = Path(f"{LOG_DIR}/{select_folder}/zeek/")
    zeek_logs  = zeek(folder_zeek)

    # ndpi
    ndpi_file = Path(f"{LOG_DIR}/{select_folder}/ndpi/ndpi_summary.log")
    ndpi_summary = ndpi(ndpi_file)

    # SUMMARY
    ######################################################

   # get data suricata
    suricata_file = f"{LOG_DIR}/{select_folder}/suricata/eve.json"

    eve_file_suricata = Path(suricata_file).is_file()


    if eve_file_suricata:
        all_suricata_events, only_suricata_alert, suricata_alert_count = suricata(
            suricata_file
        )


    # LOGS
    ##################################
    st.subheader(f"Logs pcap: {st.session_state.key}")
    st.html("<hr></hr>")


    if eve_file_suricata:
        st.subheader("Suricata")

        with st.expander("alert only", expanded=False):
            st.dataframe(
                only_suricata_alert,
                height=700,
            )

        with st.expander("all event", expanded=False):
            st.dataframe(all_suricata_events, height=700)

    # ZEEK
    st.subheader("Zeek")
    folder_zeek = Path(f"{LOG_DIR}/{select_folder}/zeek/")

    #zeek_logs = zeek(folder_zeek)
    for log in zeek_logs:
        file = log["file_name"]
        df = log["df"]
        with st.expander(f"{file} ({len(df)})", expanded=False):
            st.dataframe(df, height=700)

    # nDPI
    st.subheader("nDPI")
    with st.expander("nDPI", expanded=False):
        st.code(ndpi_summary, language='text')



else:
    pass
