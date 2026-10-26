import ijson

file_path = "/home/sb/pcap_analyzer/tools/json_feed_retro_all.json"
out_path  = "retro.intel"

with open(file_path, "rb") as fin, open(out_path, "w", encoding="utf-8") as fout:
    fout.write("#fields\tindicator\tindicator_type\tmeta.source\n")
    for ioc in ijson.items(fin, "item"):
        t = ioc.get("type")
        if   t == "File":       indicator = "Intel::FILE_HASH"
        elif t == "DomainName": indicator = "Intel::DOMAIN"
        elif t == "IPAddress":  indicator = "Intel::ADDR"
        elif t == "URL":        indicator = "Intel::URL"
        else:
            print(f"ERROR ioc type: {t!r}")
            continue
        try:
            value = ioc["keys"][0].get("value")
        except (KeyError, IndexError, TypeError) as ex:
            print(f"bad structure: {ex} :: {ioc}")
            continue
        fout.write(f"{value}\t{indicator}\tfstec_ioc\n")
