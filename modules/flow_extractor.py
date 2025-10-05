from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd
import numpy as np
from collections import defaultdict
from tqdm import tqdm

def extract_flow(pcap_path):
    """
    Extrae flujos desde un pcap y genera métricas por flujo.
    Devuelve un DataFrame con columnas para reporte y para el modelo.
    """

    packets = rdpcap(pcap_path)
    flows = defaultdict(list)

    # Procesar paquetes
    for pkt in tqdm(packets, desc="Procesando flujos"):
        try:
            if IP not in pkt:
                continue

            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            proto = pkt[IP].proto

            if TCP in pkt:
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                flags = pkt[TCP].flags
            elif UDP in pkt:
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
                flags = 0
            else:
                src_port = 0
                dst_port = 0
                flags = 0

            length = len(pkt)
            time = float(pkt.time)

            direction = "fwd" if src_port < dst_port else "bwd"
            key = (src_ip, dst_ip, src_port, dst_port, proto)

            flows[key].append((time, length, direction, flags))

        except Exception as e:
            print(f"[!] Error procesando paquete: {e}")
            continue

    # Calcular métricas por flujo
    flow_data = []

    for (src_ip, dst_ip, src_port, dst_port, proto), pkts in tqdm(flows.items(), desc="Calculando métricas"):
        times = [p[0] for p in pkts]
        sizes = [p[1] for p in pkts]
        dirs = [p[2] for p in pkts]
        flags_list = [p[3] for p in pkts]

        fwd_sizes = [sizes[i] for i in range(len(sizes)) if dirs[i] == "fwd"]
        bwd_sizes = [sizes[i] for i in range(len(sizes)) if dirs[i] == "bwd"]
        fwd_times = [times[i] for i in range(len(times)) if dirs[i] == "fwd"]
        bwd_times = [times[i] for i in range(len(times)) if dirs[i] == "bwd"]

        # Flow Duration
        start_time = min(times) if times else 0
        end_time = max(times) if times else 0
        flow_duration = (end_time - start_time) * 1000  # ms

        # === Forward Metrics ===
        fwd_pkt_len_min = min(fwd_sizes) if fwd_sizes else 0
        fwd_pkt_len_max = max(fwd_sizes) if fwd_sizes else 0
        fwd_pkt_len_mean = np.mean(fwd_sizes) if fwd_sizes else 0
        fwd_pkt_len_std = np.std(fwd_sizes) if fwd_sizes else 0

        if len(fwd_times) > 1:
            fwd_iats = np.diff(sorted(fwd_times))
            fwd_iat_min = np.min(fwd_iats)
            fwd_iat_max = np.max(fwd_iats)
            fwd_iat_mean = np.mean(fwd_iats)
            fwd_iat_std = np.std(fwd_iats)
        else:
            fwd_iat_min = fwd_iat_max = fwd_iat_mean = fwd_iat_std = 0

        # === Backward Metrics ===
        bwd_pkt_len_min = min(bwd_sizes) if bwd_sizes else 0
        bwd_pkt_len_max = max(bwd_sizes) if bwd_sizes else 0
        bwd_pkt_len_mean = np.mean(bwd_sizes) if bwd_sizes else 0
        bwd_pkt_len_std = np.std(bwd_sizes) if bwd_sizes else 0

        if len(bwd_times) > 1:
            bwd_iats = np.diff(sorted(bwd_times))
            bwd_iat_min = np.min(bwd_iats)
            bwd_iat_max = np.max(bwd_iats)
            bwd_iat_mean = np.mean(bwd_iats)
            bwd_iat_std = np.std(bwd_iats)
        else:
            bwd_iat_min = bwd_iat_max = bwd_iat_mean = bwd_iat_std = 0

        # Flags (si es TCP)
        fin_flag_count = sum([(f & 0x01) != 0 for f in flags_list])
        syn_flag_count = sum([(f & 0x02) != 0 for f in flags_list])
        rst_flag_count = sum([(f & 0x04) != 0 for f in flags_list])
        psh_flag_count = sum([(f & 0x08) != 0 for f in flags_list])
        urg_flag_count = sum([(f & 0x20) != 0 for f in flags_list])

        # === General ===
        total_packets = len(sizes)
        total_bytes = sum(sizes)
        avg_packet_size = np.mean(sizes) if sizes else 0

        # === Forward extras ===
        total_fwd_packets = len(fwd_sizes)
        total_len_fwd_packets = sum(fwd_sizes)
        avg_fwd_seg_size = np.mean(fwd_sizes) if fwd_sizes else 0
        subflow_fwd_bytes = total_len_fwd_packets
        subflow_fwd_packets = total_fwd_packets
        fwd_header_len = total_fwd_packets * 20  # suponiendo header IP/TCP de 20B
        fwd_header_len2 = fwd_header_len
        act_data_pkt_fwd = len([s for s in fwd_sizes if s > 0])
        fwd_iat_total = np.sum(np.diff(sorted(fwd_times))) if len(fwd_times) > 1 else 0
        init_win_bytes_fwd = fwd_pkt_len_max  # proxy

        # === Backward extras ===
        total_bwd_packets = len(bwd_sizes)
        total_len_bwd_packets = sum(bwd_sizes)
        avg_bwd_seg_size = np.mean(bwd_sizes) if bwd_sizes else 0
        subflow_bwd_bytes = total_len_bwd_packets        
        total_len_bwd_packets = total_len_bwd_packets   
        subflow_bwd_packets = total_bwd_packets
        bwd_iat_total = np.sum(np.diff(sorted(bwd_times))) if len(bwd_times) > 1 else 0
        init_win_bytes_bwd = bwd_pkt_len_max  # proxy

        # Agregar todas las métricas
        flow_data.append({
            "Src IP": src_ip,
            "Dst IP": dst_ip,
            "Src Port": src_port,
            "Destination Port": dst_port,
            "Protocol": proto,
            "Flow Duration": flow_duration,
            "Total Packets": total_packets,
            "Total Bytes": total_bytes,
            "Average Packet Size": avg_packet_size,
            # Forward
            "Fwd Packet Length Min": fwd_pkt_len_min,
            "Fwd Packet Length Max": fwd_pkt_len_max,
            "Fwd Packet Length Mean": fwd_pkt_len_mean,
            "Fwd Packet Length Std": fwd_pkt_len_std,
            "Fwd IAT Min": fwd_iat_min,
            "Fwd IAT Max": fwd_iat_max,
            "Fwd IAT Mean": fwd_iat_mean,
            "Fwd IAT Std": fwd_iat_std,
            # Backward
            "Bwd Packet Length Min": bwd_pkt_len_min,
            "Bwd Packet Length Max": bwd_pkt_len_max,
            "Bwd Packet Length Mean": bwd_pkt_len_mean,
            "Bwd Packet Length Std": bwd_pkt_len_std,
            "Bwd IAT Min": bwd_iat_min,
            "Bwd IAT Max": bwd_iat_max,
            "Bwd IAT Mean": bwd_iat_mean,
            "Bwd IAT Std": bwd_iat_std,
            # Flags
            "FIN Flag Count": fin_flag_count,
            "SYN Flag Count": syn_flag_count,
            "RST Flag Count": rst_flag_count,
            "PSH Flag Count": psh_flag_count,
            "URG Flag Count": urg_flag_count,
            # Forward extras
            "Init_Win_bytes_forward": init_win_bytes_fwd,
            "Subflow Fwd Bytes": subflow_fwd_bytes,
            "Subflow Fwd Packets": subflow_fwd_packets,
            "Avg Fwd Segment Size": avg_fwd_seg_size,
            "Total Length of Fwd Packets": total_len_fwd_packets,
            "act_data_pkt_fwd": act_data_pkt_fwd,
            "Fwd IAT Total": fwd_iat_total,
            "Fwd Header Length": fwd_header_len,
            "Fwd Header Length.1": fwd_header_len2,
            # Backward extras
            "Init_Win_bytes_backward": init_win_bytes_bwd,
            "Subflow Bwd Bytes": subflow_bwd_bytes,               
            "Total Length of Bwd Packets": total_len_bwd_packets, 
            "Subflow Bwd Packets": subflow_bwd_packets,
            "Bwd IAT Total": bwd_iat_total,
            "Total Fwd Packets": total_fwd_packets,       
            "Avg Bwd Segment Size": avg_bwd_seg_size,     
        })

    return pd.DataFrame(flow_data)