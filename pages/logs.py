import pandas as pd
import streamlit as st
import json
import os
from pathlib import Path
import geoip2.database
import ipaddress
import re


LOG_DIR = Path("data")
folder = os.listdir(LOG_DIR)


def suricata(file):
    # Читаем eve.json построчно
    data = []
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
    uniq_ip = []
    uniq_dns = []
    for file in folder.iterdir():
        if file.is_file():
            data = []
            with open(file) as f:
                for line in f:
                    data.append(json.loads(line))

            df = pd.json_normalize(data)
            # Если conn.log то считаем саммару
            if file.name == "conn.log":
                uniq_ip = pd.unique(df[["id.orig_h", "id.resp_h"]].values.ravel())

            if file.name == "dns.log":
                uniq_dns  = df.loc[df['qtype_name'] != 'NIMLOC', ['query', 'qtype_name']]


            result.append({"file_name": file.name, "df": df})
            # with st.expander(f"{file.name} ({len(df)})", expanded=False):
            #     st.dataframe(df, height=700)
    return result, uniq_ip  , uniq_dns


def ndpi(file):
    lines = file.read_text(errors="ignore").splitlines()
    lines = lines[12:]

    protocols = []
    in_detected = False

    for line in lines:
        if "Detected protocols:" in line:
            in_detected = True
            continue

        if in_detected:
            if not line.strip():  # пустая строка - конец секции
                break

            match = re.search(r"\s+(\S+)\s+packets:\s+(\d+)", line)
            if match:
                protocol = match.group(1)
                packets = int(match.group(2))
                protocols.append({"protocol": protocol, "packets": packets})

    ### Search public IP
    df_protocols = pd.DataFrame(protocols)

    return lines, df_protocols


def search_public_ip(ip_addrf):
    ### Search public IP
    public_ip = []
    for ip in ip_addrs:
        w = ipaddress.ip_address(ip)

        if (
            not w.is_private
            and not w.is_link_local
            and not w.is_multicast
            and not w.is_loopback
        ):
            with geoip2.database.Reader("db/GeoLite2-City.mmdb") as reader:
                response = reader.city(w)

                try:
                    city = response.city.names["en"]
                except Exception:
                    city = "-"
                try:
                    country = response.country.names["en"]
                except Exception:
                    country = "-"
                try:
                    registered_country = response.registered_country.names["en"]
                except Exception:
                    registered_country = "-"
                public_ip.append(
                    {
                        "ip": str(w),
                        "сity": city,
                        "country": country,
                        "registered_country": registered_country,
                    }
                )

    df = pd.DataFrame(public_ip)

    return df


##### streamlit

select_folder = st.selectbox("select folder", folder)
st.set_page_config(layout="wide")


if select_folder != None:
    # get data suricata
    suricata_file = f"{LOG_DIR}/{select_folder}/suricata/eve.json"
    all_suricata_events, only_suricata_alert, suricata_alert_count = suricata(
        suricata_file
    )

    # get data zeek
    folder_zeek = Path(f"{LOG_DIR}/{select_folder}/zeek/")
    zeek_logs, ip_addrs , dns = zeek(folder_zeek)

    # ndpi
    ndpi_file = Path(f"{LOG_DIR}/{select_folder}/ndpi/ndpi_summary.log")
    ndpi_summary, protocols = ndpi(ndpi_file)

    # SUMMARY
    ######################################################

    ### Suricata
    suricata_alert_count = suricata_alert_count.to_frame().reset_index()
    # переименовал колонку потому что когда в название точка он не строил
    suricata_alert_count = suricata_alert_count.rename(
        columns={"alert.severity": "severity"}
    )

    st.header("Summary")
    st.html("<hr></hr>")
    st.caption("Suricata alerts")
    st.bar_chart(
        suricata_alert_count, x="severity", y="count", horizontal=True, sort=False
    )

    # DPI Protocols
    st.caption("DPI protocols")
    st.bar_chart(protocols, x="protocol", y="packets", horizontal=True)

    # DNS 
    st.caption("DNS")
    st.dataframe(dns)

    # Public IP
    st.caption("Public Ip")
    df_public_ip = search_public_ip(ip_addrs)
    st.dataframe(df_public_ip)

    # LOGS
    ##################################
    st.header("Logs")
    st.html("<hr></hr>")

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

    # zeek_logs = zeek(folder_zeek)
    for log in zeek_logs:
        file = log["file_name"]
        df = log["df"]
        with st.expander(f"{file} ({len(df)})", expanded=False):
            st.dataframe(df, height=700)

    # nDPI
    st.subheader("nDPI")
    with st.expander("nDPI", expanded=False):

        st.code("\n".join(ndpi_summary))



else:
    pass
