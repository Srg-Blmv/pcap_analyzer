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

# берем файл и возвращаем DF


def suricata_get_df(file):
    # если eve.json ceществует
    if Path(file).is_file():
        # Читаем eve.json построчно
        data = []
        df_alert = []
        uniq_alert = []

        severity_counts = []

        with open(file) as f:
            for line in f:
                data.append(json.loads(line))

        # # Превращаем в DataFrame
        df = pd.json_normalize(data)  # нормализует вложенные поля
        # делаем только алерты
       # df_alert = df[df["event_type"] == "alert"].copy()

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
        # for c in cols:
        #     if c not in df_alert.columns:
        #         df_alert[c] = ""

       # df_alert = df_alert[cols].reset_index(drop=True)
        # Количество алертов в зависимости от критичности
        # severity_counts = df_alert["alert.severity"].value_counts().sort_index()

        # Уникальные алерты с критичность 3
        # uniq_alert = df_alert[['src_ip', 'src_port',
        #                    'dest_ip', 'dest_port', 'proto', 'app_proto', 'alert.signature']].drop_duplicates().reset_index(drop=True)

        return df  # , df_alert, severity_counts, uniq_alert
    else:
        return None

# ZEEK DNS IP
def zeek(folder):
    # ZEEK
    uniq_ip = []
    uniq_dns = []
    conn_log =  Path(f"{folder}/conn.log")
    dns_log =  Path(f"{folder}/dns.log")
    if conn_log.is_file():
        with open(conn_log) as f:
            data=[]
            for line in f:
                data.append(json.loads(line))
        df = pd.json_normalize(data)
        uniq_ip = pd.unique(df[["id.orig_h", "id.resp_h"]].values.ravel())
    else:
        uniq_ip = None


    if dns_log.is_file():
        with open(dns_log) as f:
            data=[]
            for line in f:
                data.append(json.loads(line))
        df = pd.json_normalize(data)
        # uniq_dns  = df.loc[df['qtype_name'] != 'NIMLOC', ['query', 'qtype_name']]
        uniq_dns = df[['query', 'qtype_name']].drop_duplicates()
    else:
        uniq_dns = None
    return  uniq_ip, uniq_dns


# zeek intel alerts
def zeek_get_alerts(folder):
    zeek_alerts = []
    intel_file = Path(f"{folder}/intel.log")
    if intel_file.is_file():
        with open(intel_file) as f:
            data=[]
            for line in f:
                data.append(json.loads(line))
        zeek_alerts = pd.json_normalize(data)
        return zeek_alerts
    else:
        return None

# ndpix
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

    # Search public IP
    df_protocols = pd.DataFrame(protocols)

    return lines, df_protocols


def search_public_ip(ip_addrs):
    # Search public IP
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
    if df.empty:
        return  None
    return df


# NDPI обрабатываем d
def ndpi_protocol_pie(protocols, col):
    # DPI Protocols
    height = "400px"
    protocols_sorted = protocols.sort_values('packets', ascending=True)

    if len(protocols) > 10:
        height = "600px"
        fig = px.bar(
            protocols.sort_values('packets'),
            y='protocol',
            x='packets',
            orientation='h',
            title='nDPI',
            height=600,
            text_auto=True
        )
        fig.update_layout(margin=dict(l=0, r=0, t=30, b=0))
        fig.update_xaxes(type="log")
        fig.update_xaxes(visible=False)  # скрыть вообще всё на оси X
        fig.update_layout(yaxis={'categoryorder': 'total ascending'})
        fig.update_traces(textposition='outside')
        with col1:
            st.plotly_chart(fig, width="stretch", config={
                            "displayModeBar": False})

    else:
        options_ndpi = {
            "title": {"text": "nDPI", "subtext": "", "left": "right"},
            "tooltip": {"trigger": "item"},
            "legend": {"orient": "vertical", "left": "left", },
            "series": [
                {
                    "name": "packets",
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
                        {
                            "value": row['packets'],
                            "name": f"{(row['protocol'])}"
                        }
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
        with col:
            st_echarts(options=options_ndpi, height=height)

#suricata Files
def suricata_get_fileinfo(suricata_df):
    fileinfo = []
    # копируем только алерты
    fileinfo = suricata_df[suricata_df["event_type"] == "fileinfo"].copy().reset_index(drop=True)
    fileinfo.dropna(how="all", axis=1, inplace=True)
    if fileinfo.empty:
        return None
    return fileinfo

# suricata anamoly
def suricata_get_anomaly(suricata_df):
    anomaly = []
    # копируем только алерты
    anomaly = suricata_df[suricata_df["event_type"] == "anomaly"].copy().reset_index(drop=True)
    anomaly.dropna(how="all", axis=1, inplace=True)
    if anomaly.empty:
        return None
    return anomaly




#suricata Alers
def suricata_get_alerts(suricata_df):
    df_alert = []
    uniq_alert = []
    # копируем только алерты
    df_alert = suricata_df[suricata_df["event_type"] == "alert"].copy()
    if df_alert.empty:
        return None, None
    else:
        # Если в логах нет  полей такой создатим и напишем пустое значение
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
        for c in cols:
            if c not in df_alert.columns:
                df_alert[c] = ""

        df_alert = df_alert[cols].reset_index(drop=True)

        # Количество алертов в зависимости от критичности
        suricata_alert_count = df_alert["alert.severity"].value_counts(
        ).sort_index()
    
        # Переделываем из serial в DF
        suricata_alert_count = suricata_alert_count.to_frame().reset_index()




        # Уникальные алерты
        # cчитаем строк в группе по которой делаем drop
        counts = df_alert.groupby( ['src_ip', 
                         'dest_ip', 'alert.signature'] ).size().reset_index(name='count')
        
       
        # Удаляем дубликаты ПО 3 ключам, но БЕРЁМ ВСЕ столбцы
        uniq_alert = df_alert.drop_duplicates(subset=['src_ip', 'dest_ip', 'alert.signature']).reset_index(drop=True)

        # Объединяем уникальные строки с колонкой с количеством
        uniq_alert = uniq_alert.merge(counts, on=['src_ip', 'dest_ip', 'alert.signature']).sort_values("alert.severity")
        # По скольку объеденили не по 5tupl Src портв дропнем
        # uniq_alert.drop("src_port", axis=1, inplace=True)
        # uniq_alert.drop("payload", axis=1, inplace=True)
        return suricata_alert_count, uniq_alert


def suricata_pie(suricata_alerts_count, col):

    severity_colors = {
        1: "#ff4444",
        2: "#ffaa44",
        3: "#44aaff",
    }

    options_suricata = {
        "title": {"text": "suricata alert", "subtext": "", "left": "right"},
        "tooltip": {"trigger": "item"},
        "legend": {"orient": "vertical", "left": "left", },
        "series": [
            {
                "name": "count",
                "type": "pie",
                # "radius": ["40%", "70%"],
                "radius": "70%",
                "avoidLabelOverlap": False,
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
                    {
                        "value": row['count'],
                        "name": f"Severity {int(row['alert.severity'])}",
                        "itemStyle": {"color": severity_colors.get(int(row['alert.severity']), "#999999")}
                    }
                    for _, row in suricata_alerts_count.iterrows()
                ],
                "color": ["#ff4444", "#ffaa44", "#44aaff"],
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

    with col:
        st_echarts(options=options_suricata, height="400px")

    # st.dataframe(
    #     suricata_alert_count,
    #     height=400,
    # )


# files + http.log
def http_files(folder_zeek):
    
    http_cols = ['id.orig_h','id.resp_h','id.resp_p','method', 'host', 'uri', 'status_code', 'resp_mime_types', 'resp_fuids']
    files_coils_http = ['source','analyzers', 'duration', 'sha1','fuid']
    #if 'HTTP' in uniq_protos.values:
    path = f"{folder_zeek}/http.log"
    if Path(path).is_file():
        # Создаем DF для http.log
        with open(path, 'r') as f:
            data = [json.loads(line.strip()) for line in f if line.strip()]
        # Создаём DataFrame
        df_http_log = pd.DataFrame(data)
        #resp_fuids в http храниться  в виде списка. exlode его разворачивает и дропаем все resp_fuids в которых нету значений.
        df_http_log = df_http_log.explode('resp_fuids').dropna(subset=['resp_fuids'])
        # оставляем только нужные данные а http.logs .reindex это если не все поля присуствуют в логе
        df_http_log = df_http_log.reindex(columns=http_cols)
        # берём только HTTP из files.log и сразу отшибаем не нужные столбцы
        df_files_http = df_files[df_files['source'] == 'HTTP'].reindex(columns=files_coils_http)

        # делаем join
        result_df = df_http_log.merge(
            df_files_http,
            left_on='resp_fuids',
            right_on='fuid',
            how='inner'
        )
        result_df.drop(columns=['resp_fuids'], inplace=True)
        st.badge(f"http Zeek: {len(result_df)}")
        st.dataframe(result_df)


# files + ftp.log
def ftp_files(folder_zeek):
    
    ftp_cols = ['id.orig_h','id.resp_h','id.resp_p','user','password','command', 'reply_msg', 'arg', 'mime_types','fuid']
    files_coils_http = ['source','analyzers', 'duration', 'sha1','fuid']
    path = f"{folder_zeek}/ftp.log"
    if Path(path).is_file():
        # Создаем DF для ftp.log
        with open(path, 'r') as f:
            data = [json.loads(line.strip()) for line in f if line.strip()]
        # Создаём DataFrame
        df_ftp_log = pd.DataFrame(data)
        # оставляем только нужные данные а ftp.logs .reindex это если не все поля присуствуют в логе  и дропаем строки если нет fuid
        df_ftp_log = df_ftp_log.reindex(columns=ftp_cols).dropna(subset=['fuid'])
        # берём только ftp из files.log и сразу отшибаем не нужные столбцы
        df_files_http = df_files[df_files['source'] == 'FTP_DATA'].reindex(columns=files_coils_http)
        # делаем join
        result_df = df_ftp_log.merge(
            df_files_http,
            left_on='fuid',
            right_on='fuid',
            how='inner'
        )
        st.badge(f"ftp Zeek: {len(result_df)}")
        st.dataframe(result_df)



# ========= MAIN ===============
def change_folden():
    st.session_state.key =  st.session_state.new_folden

select_folder = st.session_state.key
st.selectbox("select folder", folder, on_change=change_folden, key='new_folden', index=None, placeholder="Выберети папку") 

st.set_page_config(layout="wide")




if select_folder != None:
    # get data zeek
    folder_zeek = Path(f"{LOG_DIR}/{select_folder}/zeek/")
    ip_addrs, dns = zeek(folder_zeek)

    # ndpi
    ndpi_file = Path(f"{LOG_DIR}/{select_folder}/ndpi/ndpi_summary.log")
    ndpi_summary, protocols = ndpi(ndpi_file)

   # get data suricata
    suricata_file = f"{LOG_DIR}/{select_folder}/suricata/eve.json"
    suricata_df = suricata_get_df(suricata_file)

    st.subheader(f"Summary pcap: {st.session_state.key}")
    st.html("<hr></hr>")
    col1, col2, = st.columns(2, border=True)


    # cтроим пирог протоколов
    ndpi_protocol_pie(protocols, col1)


    # если датасет не пустой, и если если есть алерты строим пирог сурикаты
    if suricata_df is not None:
        fileinfo = suricata_get_fileinfo(suricata_df)
        suricata_anomaly = suricata_get_anomaly(suricata_df)
        suricata_alerts_count, uniq_alert = suricata_get_alerts(suricata_df)
        if suricata_alerts_count is not None:
            suricata_pie(suricata_alerts_count, col2)
            st.badge(f"uniq suricata alert: {len(uniq_alert)}")
            st.caption("Уникальные алерты сукариты (5tuple + proto + app_proto + alert.signature)" )
            st.dataframe(uniq_alert,hide_index=True,column_config={"payload": None, "src_port": None})
        else:
            with col2:
                st.markdown(
                "<div style='text-align: center;'>suricata no alerts</div>",
                unsafe_allow_html=True
            )
    else:
        fileinfo = None
        suricata_anomaly = None
        with col2:
            st.markdown(
                "<div style='text-align: center;'>suricata no alerts</div>",
                unsafe_allow_html=True
            )


   
    

    zeek_intel = zeek_get_alerts(folder_zeek)
    if zeek_intel is not None:
        st.badge(f"Zeek IOC alert: {len(zeek_intel)}")
        st.dataframe(zeek_intel)
    


    col1_dns, col2_public_ip, = st.columns(2, border=True)
    # DNS UNIQ
    if dns is not None:
        with col1_dns:
            st.badge(f"DNS: {len(dns)}")
            st.caption("Уникальны доменные имена  (query + qtype_name)")
            st.dataframe(dns, hide_index=True)

    # Public IP
    
    if ip_addrs is not None:
        df_public_ip = search_public_ip(ip_addrs)
        if df_public_ip is not None:
         
            with col2_public_ip:
                st.badge(f"Public IP: {len(df_public_ip)}")
                st.caption("Уникальные публичные IP адресса, GeoLite2 ")
                st.dataframe(df_public_ip, hide_index=True)

    
    # Ищем Файлы
    files_log = f"{folder_zeek}/files.log"
    if Path(files_log).is_file():
        with open(files_log, 'r') as f:
            data = [json.loads(line.strip()) for line in f if line.strip()]
        # Создаём DataFrame
        df_files = pd.DataFrame(data)
        uniq_protos = df_files["source"].drop_duplicates().reset_index(drop=True)
        st.header("Файлы")
        st.html("<hr></hr>")
        st.badge(f"zeek протоколы в которых найдены файлы: {uniq_protos.values}",color='green')
        st.caption("Файлы из Zeek files.log с данными из http/ftp")
        st.caption("Eсли таблица есть но emty значит в файле files.log есть запись, но в файле протокола нет записи о файле.")

        if 'HTTP' in uniq_protos.values:
            http_files(folder_zeek)
        if 'FTP_DATA' in uniq_protos.values:       
            ftp_files(folder_zeek)



    
    if fileinfo is not None:
        st.badge(f"suricata протоклы в которых найдены файлы: { fileinfo["app_proto"].drop_duplicates().reset_index(drop=True).values}", color="green")
        st.badge(f"suricata  fileinfo: {len(fileinfo)}")
        st.dataframe(fileinfo)

    # Ищем Аномалии
    files_log = f"{folder_zeek}/weird.log"
    if Path(files_log).is_file():
        with open(files_log, 'r') as f:
            data = [json.loads(line.strip()) for line in f if line.strip()]
        # Создаём DataFrame
        zeek_anomaly = pd.DataFrame(data)
        st.header("Аномалии")
        st.html("<hr></hr>")
        st.badge(f"zeek weird: {len(zeek_anomaly)}")
        st.dataframe(zeek_anomaly)


    if suricata_anomaly is not None:
        st.badge(f"suricata anomaly: {len(suricata_anomaly)}")
        st.dataframe(suricata_anomaly)
    

else:
    pass
