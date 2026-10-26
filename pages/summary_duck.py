import ipaddress
import json
import os
import re
import subprocess
from pathlib import Path

import geoip2.database
import pandas as pd
import plotly.express as px
import streamlit as st
from streamlit_echarts import st_echarts

import duckdb



LOG_DIR = Path("data")
folder = os.listdir(LOG_DIR)

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

            match = re.search(r"^\s*(\S+).*\bflows:\s+(\d+)", line)
            if match:
                protocol = match.group(1)
                flows = int(match.group(2))
                protocols.append({"protocol": protocol, "flows": flows})

    # Search public IP
    df_protocols = pd.DataFrame(protocols)

    return lines, df_protocols

def ndpi_protocol_pie(protocols):
    # DPI Protocols
    height = "400px"
    protocols_sorted = protocols.sort_values("flows", ascending=True)

    if len(protocols) > 10:
        height = "600px"
        fig = px.bar(
            protocols.sort_values("flows"),
            y="protocol",
            x="flows",
            orientation="h",
            title="nDPI",
            height=600,
            text_auto=True,
        )
        fig.update_layout(margin=dict(l=0, r=0, t=30, b=0))
        fig.update_xaxes(type="log")
        fig.update_xaxes(visible=False)  # скрыть вообще всё на оси X
        fig.update_layout(yaxis={"categoryorder": "total ascending"})
        fig.update_traces(textposition="outside")
        st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})

    else:
        options_ndpi = {
            "title": {"text": "nDPI", "subtext": "", "left": "right"},
            "tooltip": {"trigger": "item"},
            "legend": {
                "orient": "vertical",
                "left": "left",
            },
            "series": [
                {
                    "name": "flows",
                    "type": "pie",
                    "radius": "70%",
                    "avoidLabelOverlap": True,
                    "itemStyle": {
                        "borderRadius": 10,
                        "borderColor": "#fff",
                        "borderWidth": 2,
                    },
                    # "label": {"show": True, "position": "center"},
                    "emphasis": {
                        "label": {"show": True, "fontSize": 40, "fontWeight": "bold"}
                    },
                    "labelLine": {"show": True},
                    "data": [
                        {"value": row["flows"], "name": f"{(row['protocol'])}"}
                        for _, row in protocols_sorted.iterrows()
                    ],
                    "emphasis": {
                        "itemStyle": {
                            "shadowBlur": 10,
                            "shadowOffsetX": 0,
                            "shadowColor": "rgba(0, 0, 0, 0.5)",
                        }
                    },
                }
            ],
            "backgroundColor": "rgba(0, 0, 0, 0)",  # Transparent background
        }
        st_echarts(options=options_ndpi, height=height)


def suricata_uniq_alert(file):
    query = f"""
    SELECT
        any_value("timestamp")    AS "timestamp",
        src_ip,
        dest_ip,
        alert.signature,
        any_value(alert.severity) AS "alert.severity",
        any_value(src_port)       AS src_port,
        any_value(dest_port)      AS dest_port,
        any_value(proto)          AS proto,
        any_value(app_proto)      AS app_proto,
        any_value(alert.signature_id)   AS signature_id,
        count(*) AS count
    FROM read_json('{file}')
    WHERE event_type = 'alert'
    GROUP BY src_ip, dest_ip, alert.signature
    ORDER BY "alert.severity", alert.signature
    """

    # Выполняем и сразу получаем DataFrame
    try:
        df = duckdb.sql(query).df()
        return df
    except:
        return None


def zeek_get_alerts(folder):
    intel_file = Path(f"{folder}/intel.log")
    if intel_file.is_file():
        query = f"""
            SELECT
                any_value("id.orig_h")           AS orig_h,
                any_value("id.orig_p")           AS orig_p,
                any_value("id.resp_h")           AS resp_h,
                any_value("id.resp_p")           AS resp_p,
                "seen.indicator"                 AS indicator,
                any_value("seen.indicator_type") AS indicator_type,
                any_value(sources)               AS sources,
                COUNT(*)                         AS count
            FROM read_json('{intel_file}')
            GROUP BY "seen.indicator"
        """
        try:
            df = duckdb.sql(query).df()
            return df
        except Exception as ex:
            print(ex)
            return None

    else:
        return None


def select_all_from_parquet(file):
    if file.is_file():
        query = f"""
            SELECT
            *
            FROM read_parquet('{file}')
        """
        try:
            df = duckdb.sql(query).df()
            return df
        except Exception as ex:
            print(ex)
            return None

    else:
        return None




def uniq_col(file,col):
    if file.is_file():
        query = f"""
            SELECT DISTINCT
            {col}
            FROM read_parquet('{file}')
        """
        try:
            df = duckdb.sql(query).df()
            return df
        except Exception as ex:
            print(ex)
            return None

    else:
        return None



# ========= MAIN ===============
if "key" not in st.session_state:
    st.session_state.key = None


def change_folden():
    st.session_state.key = st.session_state.new_folden


select_folder = st.session_state.key
st.selectbox(
    "select folder",
    folder,
    on_change=change_folden,
    key="new_folden",
    index=None,
    placeholder="Выберети папку",
)

st.set_page_config(layout="wide")


if select_folder != None:

    folder_zeek = Path(f"{LOG_DIR}/{select_folder}/zeek/")

    suricata_file = f"{LOG_DIR}/{select_folder}/suricata/eve.json"





    # NDPI
    ndpi_file = Path(f"{LOG_DIR}/{select_folder}/ndpi/ndpi_summary.log")
    ndpi_json = Path(f"{LOG_DIR}/{select_folder}/ndpi/ndpi.json")
    ndpi_summary, protocols = ndpi(ndpi_file)
    ndpi_protocol_pie(protocols)



    # УНИКАЛЬНЫЕ АЛЕРТЫ СУРИКАТА
    df_suricata_uniq_alert = suricata_uniq_alert(suricata_file)
    if df_suricata_uniq_alert is not None:
        st.badge(f"uniq suricata alert: {len(df_suricata_uniq_alert)}")
        st.caption(
            "Уникальные алерты сукариты (5tuple + proto + app_proto + alert.signature)"
        )
        st.dataframe(
            df_suricata_uniq_alert,
            hide_index=True,
            height= 600
            #column_config={"payload": None, "src_port": None},
        )

    # ZEEK

    zeek_intel = zeek_get_alerts(folder_zeek)
    if zeek_intel is not None:
        st.badge(f"Zeek IOC alert: {len(zeek_intel)}")
        st.caption(
            "Уникальные алерты zeek ioc (сгрупированны по seen.indicator)"
        )
        st.dataframe(zeek_intel)



    (
        col1_dns,
        col2_public_ip,
    ) = st.columns(2, border=True)


    dns_uniq_parquet = Path(f"{LOG_DIR}/{select_folder}/summary/uniq_dns.parquet")
    dns = select_all_from_parquet(dns_uniq_parquet)
    if dns is not None:
        with col1_dns:
            st.badge(f"DNS: {len(dns)}")
            st.caption("Уникальны доменные имена  (query + qtype_name + rcode_name)")
            st.dataframe(dns, hide_index=True)


    public_ip_parquet = Path(f"{LOG_DIR}/{select_folder}/summary/public_ip.parquet")
    public_ip = select_all_from_parquet(public_ip_parquet)
    if public_ip is not None:
        with col2_public_ip:
            st.badge(f"Public IP: {len(public_ip)}")
            st.caption("Уникальные публичные IP адресса, GeoLite2 ")
            st.dataframe(public_ip, hide_index=True)




    http_files_parquet = Path(f"{LOG_DIR}/{select_folder}/summary/http_files.parquet")
    http_files = select_all_from_parquet(http_files_parquet)
    if http_files is not None:
        st.badge("http uniq mime types:", color="orange")
        st.write(", ".join(map(str, uniq_col(http_files_parquet, "mime_type").squeeze().tolist())))
        st.badge(f"http files: {len(http_files)}")
        st.dataframe(http_files, hide_index=True)



    # clamAV

    clamAV_log = f"{LOG_DIR}/{select_folder}/clamav.log"
    clamAV_log_file = Path(clamAV_log).is_file()
    if clamAV_log_file:
        with open(clamAV_log, 'r', encoding='utf-8') as f:
            content = f.read()
        lines = content.strip().splitlines()          # output — весь текст summary
        infected = int(lines[-6].split(":")[1].strip())
        st.badge(f"clamAV infected: {infected}")

        with st.expander("clamAV summary", expanded=False):
            st.code(content, language='text')



    ndpi_file_parquet = Path(f"{LOG_DIR}/{select_folder}/summary/ndpi_risk_session.parquet")
    ndpi_df = select_all_from_parquet(ndpi_file_parquet)
    if ndpi_df is not None:
        st.badge(f"ndpi risk session: {len(ndpi_df)}")
        st.dataframe(ndpi_df, hide_index=True)





else:
    pass
