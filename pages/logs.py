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
    uniq_ip = []
    uniq_dns = []
    for file in folder.iterdir():
        if file.is_file():
            data = []
            with open(file) as f:
                for line in f:
                    data.append(json.loads(line))

            df = pd.json_normalize(data)
            # Если conn.log то считаем саммари
            if file.name == "conn.log":
                uniq_ip = pd.unique(df[["id.orig_h", "id.resp_h"]].values.ravel())

            if file.name == "dns.log":
                #uniq_dns  = df.loc[df['qtype_name'] != 'NIMLOC', ['query', 'qtype_name']]
                uniq_dns  = df[['query','qtype_name']].drop_duplicates()


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


def change_folden():
    st.session_state.key =  st.session_state.new_folden

select_folder = st.session_state.key
st.selectbox("select folder", folder, on_change=change_folden, key='new_folden', index=None, placeholder="Выберети папку") 

st.set_page_config(layout="wide")


if select_folder != None:

    # get data zeek
    folder_zeek = Path(f"{LOG_DIR}/{select_folder}/zeek/")
    zeek_logs, ip_addrs , dns = zeek(folder_zeek)

    # ndpi
    ndpi_file = Path(f"{LOG_DIR}/{select_folder}/ndpi/ndpi_summary.log")
    ndpi_summary, protocols = ndpi(ndpi_file)

    # SUMMARY
    ######################################################

   # get data suricata
    suricata_file = f"{LOG_DIR}/{select_folder}/suricata/eve.json"

    eve_file_suricata = Path(suricata_file).is_file()
    

    if eve_file_suricata:
        all_suricata_events, only_suricata_alert, suricata_alert_count = suricata(
            suricata_file
        )

    #     st.header("Summary")
    #     st.html("<hr></hr>")

    # # DPI Protocols

    #     col1, col2, = st.columns(2,border=True)
    #     height = "400px"
    #     protocols_sorted = protocols.sort_values('packets', ascending=True)
    #     if len(protocols) > 10:
    #         height = "600px"
    #         fig = px.bar(
    #             protocols.sort_values('packets'),
    #             y='protocol',
    #             x='packets',
    #             orientation='h',
    #             title='nDPI',
    #             height=600,
    #             text_auto=True
    #         )
    #         fig.update_layout( margin=dict(l=0, r=0, t=30, b=0))
    #         fig.update_xaxes(type="log")
    #         fig.update_xaxes(visible=False)  # скрыть вообще всё на оси X
    #         fig.update_layout(yaxis={'categoryorder': 'total ascending'})
    #         fig.update_traces(textposition='outside')
    #         with col1:
    #            st.plotly_chart(fig, width="stretch", config={"displayModeBar": False})

    #     else:
    #         options_ndpi = {
    #             "title": {"text": "nDPI", "subtext": "", "left": "right"},
    #             "tooltip": {"trigger": "item"},
    #             "legend": {"orient": "vertical", "left": "left", },
    #             "series": [
    #                 {
    #                     "name": "packets",
    #                     "type": "pie",
    #                     "radius": "70%",
    #                     "avoidLabelOverlap": True,
    #                     "itemStyle": {
    #                         "borderRadius": 10,
    #                         "borderColor": "#fff",
    #                         "borderWidth": 2,
    #                     },
    #                     #"label": {"show": True, "position": "center"},
    #                     "emphasis": {
    #                         "label": {"show": True, "fontSize": 40, "fontWeight": "bold"}
    #                     },
    #                 "labelLine": {"show": True},
    #                     "data": [
    #                     {
    #                         "value": row['packets'], 
    #                         "name": f"{(row['protocol'])}"
    #                     }
    #                     for _, row in protocols_sorted.iterrows()
    #                 ],
    #                     "emphasis": {
    #                         "itemStyle": {
    #                             "shadowBlur": 10,
    #                             "shadowOffsetX": 0,
    #                             "shadowColor": "rgba(0, 0, 0, 0.5)",
    #                         }
    #                     },
    #                 }
    #             ],
    #             "backgroundColor": "rgba(0, 0, 0, 0)",  # Transparent background
    #         }   
    #         with col1:
    #             st_echarts(options=options_ndpi, height=height)


    # ### Suricata
    #     suricata_alert_count = suricata_alert_count.to_frame().reset_index()
    #     # переименовал колонку потому что когда в название точка он не строил
    #     # suricata_alert_count = suricata_alert_count.rename(
    #     #     columns={"alert.severity": "severity"}
    #     # )

    #     severity_colors = {
    #         1: "#ff4444",  
    #         2: "#ffaa44",  
    #         3: "#44aaff",  
    #     }

    #     options_suricata = {
    #     "title": {"text": "suricata alert", "subtext": "", "left": "right"},
    #     "tooltip": {"trigger": "item"},
    #     "legend": {"orient": "vertical", "left": "left", },
    #     "series": [
    #         {
    #             "name": "count",
    #             "type": "pie",
    #             "radius": ["40%", "70%"],
    #             "avoidLabelOverlap": False,
    #             "itemStyle": {
    #                 "borderRadius": 10,
    #                 "borderColor": "#fff",
    #                 "borderWidth": 2,
    #             },
    #             #"label": {"show": True, "position": "center"},
    #             "emphasis": {
    #                 "label": {"show": True, "fontSize": 40, "fontWeight": "bold"}
    #             },
    #         "labelLine": {"show": True},
    #              "data": [
    #             {
    #                 "value": row['count'], 
    #                 "name": f"Severity {int(row['alert.severity'])}",
    #                 "itemStyle": {"color": severity_colors.get(int(row['alert.severity']), "#999999")}
    #             }
    #             for _, row in suricata_alert_count.iterrows()
    #         ],
    #          "color": ["#ff4444", "#ffaa44", "#44aaff"], 
    #             "emphasis": {
    #                 "itemStyle": {
    #                     "shadowBlur": 10,
    #                     "shadowOffsetX": 0,
    #                     "shadowColor": "rgba(0, 0, 0, 0.5)",
    #                 }
    #             },
    #         }
    #     ],
    #     "backgroundColor": "rgba(0, 0, 0, 0)",  # Transparent background
    # }   
        

    #     with col2:
    #         st_echarts(options=options_suricata, height=height)


    #     # st.bar_chart(
    #     #     suricata_alert_count, x="severity", y="count", horizontal=True, sort=False
    #     # )



    # # DNS UNIQ
    # st.caption("Unique Domain Name")
    # st.dataframe(dns,hide_index=True)

    # # Public IP
    # st.caption("Public Ip")
    # df_public_ip = search_public_ip(ip_addrs)
    # st.dataframe(df_public_ip, hide_index=True)

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
