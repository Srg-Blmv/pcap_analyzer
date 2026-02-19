import pandas as pd
import streamlit as st
import json
import os
from pathlib import Path


LOG_DIR = Path("data")
folder = os.listdir(LOG_DIR)






def suricata(file):
    # Читаем eve.json построчно
    data = []
    with open(file
    ) as f:
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
    #Если в сурикате нет такой создатим и напишем пустое значение
    for c in cols:
        if c not in df_alert.columns:
            df_alert[c] = ""

    df_alert = df_alert[cols].reset_index(drop=True)



    # Количество алертов в зависимости от критичности
    severity_counts = df_alert["alert.severity"].value_counts().sort_index()
    print(severity_counts)

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
            #Если conn.log то считаем саммару
            if file.name == 'conn.log':
                uniq_ip = pd.unique(df[["id.orig_h", "id.resp_h"]].values.ravel())
                uniq_dst_port = pd.unique(df[["id.resp_p"]].values.ravel())
                print("uniq_ip: ", uniq_ip)
                print("uniq_dst_port: ", uniq_dst_port)

            result.append({
                "file_name": file.name,
                "df": df
            })
            # with st.expander(f"{file.name} ({len(df)})", expanded=False):
            #     st.dataframe(df, height=700)
    return result


def ndpi(file):
    lines = file.read_text(errors="ignore").splitlines()
    lines = lines[12:]
    return lines




##### streamlit

select_folder = st.selectbox("выбирете папку", folder)
st.set_page_config(layout="wide")


if select_folder != None:
    suricata_file = f'{LOG_DIR}/{select_folder}/suricata/eve.json'
    all_suricata_events, only_suricata_alert, suricata_alert_count = suricata(suricata_file)



    st.subheader("Suricata")
    with st.expander("Все события", expanded=False):
        st.dataframe(all_suricata_events, height=700)


    with st.expander("Только Алерты", expanded=False):
        st.dataframe(
            only_suricata_alert,
            height=700,
        )



    # ZEEK
    st.subheader("Zeek")
    folder_zeek = Path(f'{LOG_DIR}/{select_folder}/zeek/')

    zeek_logs = zeek(folder_zeek)
    for log in zeek_logs:
        file = log["file_name"]
        df = log["df"]
        with st.expander(f"{file} ({len(df)})", expanded=False):
            st.dataframe(df, height=700)





    st.subheader("nDPI")
    with st.expander("nDPI", expanded=False):
        ndpi_file = Path(f'{LOG_DIR}/{select_folder}/ndpi/ndpi_summary.log')  
        ndpi_summary = ndpi(ndpi_file)
        st.code("\n".join(ndpi_summary))

else:
    pass