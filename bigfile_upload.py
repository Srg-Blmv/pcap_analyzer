import os
from pathlib import Path
from datetime import datetime
import argparse
import shutil
import pandas as pd
import geoip2.database
import ipaddress
import json

LOG_DIR = Path("data")

parser = argparse.ArgumentParser()
parser.add_argument('pcap', type=str, help='path to pcap')
args = parser.parse_args()



path_pcap = Path(args.pcap)

print(path_pcap)



# что бы каждый раз  не кошмарить сделаем 1 раз и добавить в файл.

def search_public_ip(ip_addrs):
    # Search public IP
    public_ip = []
    reader = geoip2.database.Reader("db/GeoLite2-City.mmdb")
    try:
        for ip in ip_addrs:
            w = ipaddress.ip_address(ip)

            if (
                not w.is_private
                and not w.is_link_local
                and not w.is_multicast
                and not w.is_loopback
            ):
                try:
                    response = reader.city(w)
                except Exception as ex:
                    public_ip.append(
                        {
                            "ip": str(w),
                            "сity": "not found in db",
                            "country": "404",
                            "registered_country": "404",
                        }
                    )
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
    finally:
        reader.close()

    df = pd.DataFrame(public_ip)
    if df.empty:
        return None
    return df



def zeek(folder):
    # ZEEK
    uniq_ip = []
    uniq_dns = []
    conn_log = Path(f"{folder}/zeek/conn.log")
    dns_log = Path(f"{folder}/zeek/dns.log")
    if conn_log.is_file():
        with open(conn_log) as f:
            data = []
            for line in f:
                data.append(json.loads(line))
        df = pd.json_normalize(data)
        uniq_ip = pd.unique(df[["id.orig_h", "id.resp_h"]].values.ravel())
        pd.DataFrame({"ip": uniq_ip}).to_parquet(f"{folder}/summary/uniq_ip.parquet",  index=False)
        if uniq_ip is not None:
            df_public_ip = search_public_ip(uniq_ip)
            if df_public_ip is not None:
                df_public_ip.to_parquet(f"{folder}/summary/public_ip.parquet",  index=False)


    else:
        uniq_ip = None

    if dns_log.is_file():
        with open(dns_log) as f:
            data = [json.loads(line) for line in f]  # список словарей
        df = pd.json_normalize(data)

        # Все поля, которые нас интересуют
        target_cols = ["query", "qtype_name", "rcode_name", "answers"]

        # Для каждого столбца, если его нет в DataFrame – добавляем с NaN
        df = df.reindex(columns=target_cols)
        if "answers" in df.columns:
            df["answers"] = df["answers"].apply(
                lambda x: ", ".join(x) if isinstance(x, list) else x
            )

        # Теперь берём только нужные колонки и убираем дубликаты по ним
        uniq_dns = df[target_cols].drop_duplicates()
        uniq_dns.to_parquet(f"{folder}/summary/uniq_dns.parquet", index=False)

    else:
        uniq_dns = None


def http_files(folder):
    #deepseek
    #
    files_log = f"{folder}/zeek/files.log"
    if not Path(files_log).is_file():
        print(f"http file: {Path(files_log).is_file()}")
        return

    with open(files_log, "r") as f:
        data = [json.loads(line.strip()) for line in f if line.strip()]
    # Создаём DataFrame
    df_files = pd.DataFrame(data)

    http_cols = ["id.orig_h", "id.resp_h", "id.resp_p", "method",
                    "host", "uri", "status_code"]

    http_log = f"{folder}/zeek/http.log"

    if not Path(http_log).is_file():
        return

    with open(http_log, "r") as f:
        data = [json.loads(line.strip()) for line in f if line.strip()]
    df = pd.DataFrame(data).reindex(columns=http_cols + [
        "resp_fuids", "orig_fuids",
        "resp_mime_types", "orig_mime_types",
        "filename", "orig_filenames",
    ])

    def as_list(v):
        if isinstance(v, list):
            return v
        if v is None or (isinstance(v, float) and pd.isna(v)):
            return []
        return [v]

    def get_by_idx(lst, i):
        return lst[i] if i < len(lst) else None

    def flatten(df, fuids_col, mimes_col, name_col, direction):
        rows = []
        for _, r in df.iterrows():
            fuids = as_list(r.get(fuids_col))
            mimes = as_list(r.get(mimes_col))
            names = as_list(r.get(name_col))
            for i, fuid in enumerate(fuids):
                rows.append({
                    **{c: r.get(c) for c in http_cols},
                    "fuid": fuid,
                    "mime_type": get_by_idx(mimes, i),
                    "file_name": get_by_idx(names, i),
                    "direction": direction,
                })
        return pd.DataFrame(rows)

    df_resp = flatten(df, "resp_fuids", "resp_mime_types", "filename", "download")
    df_orig = flatten(df, "orig_fuids", "orig_mime_types", "orig_filenames", "upload")

    df_union = pd.concat([df_resp, df_orig], ignore_index=True)

    df_files_http = df_files[df_files["source"] == "HTTP"].reindex(
        columns=["source", "analyzers", "duration", "sha1", "fuid"]
    )
    result_df = df_union.merge(df_files_http, on="fuid", how="inner")
    result_df.to_parquet(f"{folder}/summary/http_files.parquet", index=False)


def ndpi_log(folder):
    data = []
    file = f"{folder}/ndpi/ndpi.json"
    if Path(file).is_file():
        with open(file) as f:
            lines = f.readlines()
            for line in lines:
                data.append(json.loads(line))
        rows = []
        for flow in data:
            row = {}

            row["vlan_id"] = flow.get("vlan_id", 0)
            row["src_ip"] = flow.get("src_ip", 0)
            row["dest_ip"] = flow.get("dest_ip", 0)
            row["src_port"] = flow.get("src_port", 0)
            row["dst_port"] = flow.get("dst_port", 0)
            row["L3-L4"] = flow.get("proto", "N/A")
            row["duration"] = flow.get("duration", 0)

            # xfer (если есть)
            # xfer = flow.get('xfer', {})
            # row['direction'] = xfer.get('data_ratio_str', 'N/A')
            # row['src2dst_bytes'] = xfer.get('src2dst_bytes', 0)
            # row['dst2src_bytes'] = xfer.get('dst2src_bytes', 0)
            # row['src2dst_packets'] = xfer.get('src2dst_packets', 0)
            # row['dst2src_packets'] = xfer.get('dst2src_packets', 0)

            # ndpi (если есть)
            ndpi = flow.get("ndpi", {})
            row["ndpi_proto"] = ndpi.get("proto", "Unknown")
            row["proto_by_ip"] = ndpi.get("proto_by_ip", "Unknown")
            # row['breed'] = ndpi.get('breed', 'Unknown')
            # row['encrypted'] = 'Yes' if ndpi.get('encrypted', 0) else 'No'

            # flow_risk (если есть)
            flow_risk = ndpi.get("flow_risk", {})
            if flow_risk:
                risk_names = [flow_risk[r].get("risk", "Unknown") for r in flow_risk]
                row["risks"] = ", ".join(risk_names)
            else:
                row["risks"] = "None"

            rows.append(row)
        df = pd.DataFrame(rows)  # .sort_values(by=["src_ip"])
        df.to_parquet(f"{folder}/summary/ndpi_risk_session.parquet", index=False)




if path_pcap:

    file_name = path_pcap.name
    name_pcap_dir = f'{datetime.now().strftime("%Y-%m-%d")}_{Path(file_name).stem}'
    path_dir = f'{LOG_DIR}/{name_pcap_dir}'
    full_path_file = f'{path_dir}/{file_name}'
    os.mkdir(path_dir)

    shutil.copy2(path_pcap, full_path_file)
    print(f"copy pcap: {full_path_file}")

    # suricata
    os.mkdir(f'{path_dir}/suricata')
    print("Suricata start")
    os.system(f"docker exec  suricata  suricatasc -c  'pcap-file /tmp/{name_pcap_dir}/{file_name} /tmp/{name_pcap_dir}/suricata/'   /var/run/suricata/suricata-command.socket")

    # zeek
    os.mkdir(f'{path_dir}/zeek')
    print("zeek start")
    os.system(
        #f'docker run --rm -v {os.path.abspath("data")}:/pcap  -v {os.path.abspath("zeek_conf")}:/opt   zeek/zeek:8.0  bash -c "cd /pcap/{name_pcap_dir}/zeek && zeek -C -r ../{file_name}  /opt/Zeek-Intelligence-Feeds/__load__.zeek  LogAscii::use_json=T"')
        #f'docker run --rm -v {os.path.abspath("data")}:/pcap  -v {os.path.abspath("zeek_conf")}:/opt   zeek/zeek:8.2  bash -c "cd /pcap/{name_pcap_dir}/zeek && zeek -C -r ../{file_name}  /opt/conf.zeek  LogAscii::use_json=T"')
        f'docker exec  zeek  bash -c "cd /pcap/{name_pcap_dir}/zeek && zeek -C -r ../{file_name}  /opt/conf.zeek  LogAscii::use_json=T"')



    # clamAV
    extract_files = f"{path_dir}/zeek/extract_files"
    extract_files_dir = Path(extract_files).is_dir()
    if extract_files_dir:
        print("ClamAV start")
        os.system(
        f'docker exec clamav  clamscan -r /tmp/{name_pcap_dir}/zeek/extract_files -l /tmp/{name_pcap_dir}/clamav.log ')
        os.system(
        f'docker exec clamav  chmod 666 /tmp/{name_pcap_dir}/clamav.log ')
    else:
         print("extract_files not found")


    # ndpi
    os.mkdir(f'{path_dir}/ndpi')
    print("ndpi start")
    os.system(
        f'{os.path.abspath("ndpi")}/ndpiReader -i {full_path_file} -d -F -t -K json -k {path_dir}/ndpi/ndpi.json > {path_dir}/ndpi/ndpi_summary.log 2>&1')

    print("Analysis")
    os.mkdir(f'{path_dir}/summary')
    zeek(f'{path_dir}')
    http_files(f'{path_dir}')
    ndpi_log(f'{path_dir}')



    # tshark
    os.mkdir(f'{path_dir}/tshark')
    print("tshark start")
    os.system(f'tshark -r {full_path_file} -Y ip -T fields -e ip.src -e eth.src -e  eth.src_resolved -e ip.dst -e eth.dst -e  eth.dst_resolved -E separator=, | sort -u  > {path_dir}/tshark/ipv4_dialog.csv')
