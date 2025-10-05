import pandas as pd
import numpy as np
import json

def interpret_attacks(predicted_csv, raw_csv, ratio_threshold=0.1, min_flows=100, export_json=None):
    """
    Lee CSV de predicciones y raw_flows, aplica filtros dinámicos y genera
    métricas completas para el reporte.
    Si se pasa export_json, guarda también el resultado en un archivo JSON.
    """

    # === 1. Cargar datos ===
    df_preds = pd.read_csv(predicted_csv)
    df_raw = pd.read_csv(raw_csv)

    # Merge si ambos tienen "Unnamed: 0"
    if "Unnamed: 0" in df_preds.columns and "Unnamed: 0" in df_raw.columns:
        df_preds = df_preds.merge(df_raw, on="Unnamed: 0", suffixes=("_pred", "_raw"))

    total = len(df_preds)

    # === 2. Attack summary (desde predicciones) ===
    counts = df_preds["Prediction"].value_counts()
    attack_summary = {}

    if total <= min_flows:
        labels_to_report = counts.items()
    else:
        labels_to_report = [
            (label, count) for label, count in counts.items()
            if count / total >= ratio_threshold
        ]

    for label, count in labels_to_report:
        subset = df_preds[df_preds["Prediction"] == label]
        attack_summary[label] = {
            "count": int(count),
            "ratio": round(count / total, 3),
            "unique_src_ips": int(subset["Src IP"].nunique()),
            "unique_dst_ips": int(subset["Dst IP"].nunique()),
            "top_src_ips": {k:int(v) for k,v in subset["Src IP"].value_counts().head(5).to_dict().items()},
            "top_dst_ips": {k:int(v) for k,v in subset["Dst IP"].value_counts().head(5).to_dict().items()},
            "top_dst_ports": {k:int(v) for k,v in subset["Destination Port"].value_counts().head(5).to_dict().items()}
                if "Destination Port" in subset.columns else {}
        }

    # === 3. Flow summary (desde predicciones) ===
    flow_summary = {
        "total_flows": int(total),
        "top_src_ips": {k:int(v) for k,v in df_preds["Src IP"].value_counts().head(5).to_dict().items()},
        "top_dst_ips": {k:int(v) for k,v in df_preds["Dst IP"].value_counts().head(5).to_dict().items()},
        "top_dst_ports": {k:int(v) for k,v in df_preds["Destination Port"].value_counts().head(5).to_dict().items()}
            if "Destination Port" in df_preds.columns else {},
        "total_packets": int(df_preds["Total Packets"].sum())
            if "Total Packets" in df_preds.columns else None,
        "total_bytes": int(df_preds["Total Bytes"].sum())
            if "Total Bytes" in df_preds.columns else None,
        "avg_duration": round(df_preds["Flow Duration"].mean(), 3)
            if "Flow Duration" in df_preds.columns else None,
        "avg_packet_size": round(df_preds["Average Packet Size"].mean(), 3)
            if "Average Packet Size" in df_preds.columns else None,
        "packets_per_sec": round(df_preds["Packets/s"].mean(), 3)
            if "Packets/s" in df_preds.columns else None,
        "bytes_per_sec": round(df_preds["Bytes/s"].mean(), 3)
            if "Bytes/s" in df_preds.columns else None
    }

    # === 4. Raw flow insights (desde raw_flows) ===
    raw_summary = {}
    if not df_raw.empty:
        raw_summary = {
            "protocol_distribution": {k:int(v) for k,v in df_raw["Protocol"].value_counts().head(5).to_dict().items()}
                if "Protocol" in df_raw.columns else {},
            "duration_total": int(df_raw["Flow Duration"].sum())
                if "Flow Duration" in df_raw.columns else None,
            "duration_avg": round(df_raw["Flow Duration"].mean(), 3)
                if "Flow Duration" in df_raw.columns else None,
            "top_src_ips": {k:int(v) for k,v in df_raw["Src IP"].value_counts().head(5).to_dict().items()}
                if "Src IP" in df_raw.columns else {},
            "top_dst_ips": {k:int(v) for k,v in df_raw["Dst IP"].value_counts().head(5).to_dict().items()}
                if "Dst IP" in df_raw.columns else {},
            "flags_summary": {
                "syn": int(df_raw["SYN Flag Count"].sum()) if "SYN Flag Count" in df_raw.columns else 0,
                "fin": int(df_raw["FIN Flag Count"].sum()) if "FIN Flag Count" in df_raw.columns else 0,
                "rst": int(df_raw["RST Flag Count"].sum()) if "RST Flag Count" in df_raw.columns else 0,
                "psh": int(df_raw["PSH Flag Count"].sum()) if "PSH Flag Count" in df_raw.columns else 0,
                "urg": int(df_raw["URG Flag Count"].sum()) if "URG Flag Count" in df_raw.columns else 0,
            },
            "packet_sizes": {
                "avg_packet_size": round(df_raw["Average Packet Size"].mean(), 3)
                    if "Average Packet Size" in df_raw.columns else None,
                "max_fwd_packet": int(df_raw["Fwd Packet Length Max"].max())
                    if "Fwd Packet Length Max" in df_raw.columns else None,
                "max_bwd_packet": int(df_raw["Bwd Packet Length Max"].max())
                    if "Bwd Packet Length Max" in df_raw.columns else None,
            }
        }

    # === 5. Construir reporte final ===
    report = {
        "attack_summary": attack_summary,
        "flow_summary": flow_summary,
        "raw_summary": raw_summary
    }


    # === 6. Exportar a JSON si se pidió ===
    if export_json:
        with open(export_json, "w") as f:
            json.dump(report, f, indent=4)

    return report