import os
import json
import matplotlib.pyplot as plt

from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle
)
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors


def _add_table(story, title, data, col_widths=(200, 200)):
    styles = getSampleStyleSheet()
    story.append(Paragraph(f"<b>{title}</b>", styles["Heading2"]))
    table = Table(data, colWidths=list(col_widths))
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
        ("TOPPADDING", (0, 0), (-1, 0), 6),
    ]))
    story.append(table)
    story.append(Spacer(1, 16))


def _safe_dict(d):
    return d if isinstance(d, dict) else {}


def _plot_bar(labels, values, title, outfile, rotation=45):
    plt.figure()
    plt.bar(labels, values)
    plt.title(title)
    plt.xticks(rotation=rotation, ha="right")
    plt.tight_layout()
    plt.savefig(outfile, dpi=150)
    plt.close()


def _plot_pie(labels, values, title, outfile, startangle=140):
    plt.figure()
    plt.pie(values, labels=labels, autopct="%1.1f%%", startangle=startangle)
    plt.title(title)
    plt.tight_layout()
    plt.savefig(outfile, dpi=150)
    plt.close()


def generate_report(report_json, output_pdf):
    """
    Genera un reporte PDF con tablas y gráficas a partir del JSON producido por interpret_attacks.
    Incluye:
      - Resumen de flujos
      - Resumen de ataques
      - Resumen RAW (protocolos, flags, tamaños)
      - Gráficas: distribución de ataques, top src/dst IPs, top puertos (si hay),
                  distribución de protocolos (si hay) y resumen de flags TCP (si hay)
    """
    # === 1) Cargar JSON ===
    with open(report_json, "r") as f:
        report = json.load(f)

    attack_summary = _safe_dict(report.get("attack_summary"))
    flow_summary = _safe_dict(report.get("flow_summary"))
    raw_summary = _safe_dict(report.get("raw_summary"))

    # === 2) Preparar PDF ===
    doc = SimpleDocTemplate(output_pdf, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("Reporte de Análisis de Tráfico de Red", styles["Title"]))
    story.append(Spacer(1, 12))

    # === 3) Tablas de resumen ===
    # 3.1 Flow summary
    flow_table = [
        ["Métrica", "Valor"],
        ["Total Flows", flow_summary.get("total_flows")],
        ["Total Packets", flow_summary.get("total_packets")],
        ["Total Bytes", flow_summary.get("total_bytes")],
        ["Avg Duration (s)", flow_summary.get("avg_duration")],
        ["Avg Packet Size", flow_summary.get("avg_packet_size")],
        ["Packets/s", flow_summary.get("packets_per_sec")],
        ["Bytes/s", flow_summary.get("bytes_per_sec")],
    ]
    _add_table(story, "Resumen de Flujos", flow_table, col_widths=(220, 180))

    # 3.2 Attack summary (tabla)
    attack_table = [["Etiqueta", "Count", "Ratio"]]
    for label, data in attack_summary.items():
        attack_table.append([label, data.get("count"), data.get("ratio")])
    _add_table(story, "Resumen de Ataques", attack_table, col_widths=(200, 100, 100))

    # 3.3 RAW summary (si hay)
    if raw_summary:
        raw_flow_table = [
            ["Métrica", "Valor"],
            ["Duration Total (µs)", raw_summary.get("duration_total")],
            ["Duration Promedio (µs)", raw_summary.get("duration_avg")],
            ["Avg Packet Size (raw)", (raw_summary.get("packet_sizes") or {}).get("avg_packet_size")],
            ["Max Fwd Packet (raw)", (raw_summary.get("packet_sizes") or {}).get("max_fwd_packet")],
            ["Max Bwd Packet (raw)", (raw_summary.get("packet_sizes") or {}).get("max_bwd_packet")],
        ]
        _add_table(story, "Resumen RAW", raw_flow_table, col_widths=(220, 180))

        # Top IPs desde RAW
        top_src_raw = _safe_dict(raw_summary.get("top_src_ips"))
        top_dst_raw = _safe_dict(raw_summary.get("top_dst_ips"))
        if top_src_raw:
            data = [["Top Src IP (raw)", "Count"]] + [[k, v] for k, v in top_src_raw.items()]
            _add_table(story, "Top IPs Origen (RAW)", data, col_widths=(220, 180))
        if top_dst_raw:
            data = [["Top Dst IP (raw)", "Count"]] + [[k, v] for k, v in top_dst_raw.items()]
            _add_table(story, "Top IPs Destino (RAW)", data, col_widths=(220, 180))

    # === 4) Gráficas ===
    plots_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "plots_tmp")
    os.makedirs(plots_dir, exist_ok=True)

    # 4.1 Distribución de ataques (bar)
    if attack_summary:
        labels = list(attack_summary.keys())
        counts = [attack_summary[k].get("count", 0) for k in labels]
        attack_plot = os.path.join(plots_dir, "attack_dist.png")
        _plot_bar(labels, counts, "Distribución de Ataques", attack_plot)
        story.append(Image(attack_plot, width=400, height=250))
        story.append(Spacer(1, 16))

    # 4.2 Top 5 IPs origen (flow_summary)
    top_src = _safe_dict(flow_summary.get("top_src_ips"))
    if top_src:
        src_labels = list(top_src.keys())
        src_counts = list(top_src.values())
        src_plot = os.path.join(plots_dir, "src_ips.png")
        _plot_bar(src_labels, src_counts, "Top 5 IPs Origen", src_plot)
        story.append(Image(src_plot, width=400, height=250))
        story.append(Spacer(1, 16))

    # 4.3 Top 5 IPs destino (flow_summary)
    top_dst = _safe_dict(flow_summary.get("top_dst_ips"))
    if top_dst:
        dst_labels = list(top_dst.keys())
        dst_counts = list(top_dst.values())
        dst_plot = os.path.join(plots_dir, "dst_ips.png")
        _plot_bar(dst_labels, dst_counts, "Top 5 IPs Destino", dst_plot)
        story.append(Image(dst_plot, width=400, height=250))
        story.append(Spacer(1, 16))

    # 4.4 Distribución de puertos destino (flow_summary)
    top_ports = _safe_dict(flow_summary.get("top_dst_ports"))
    if top_ports:
        ports_labels = list(top_ports.keys())
        ports_counts = list(top_ports.values())
        ports_plot = os.path.join(plots_dir, "dst_ports.png")
        _plot_pie(ports_labels, ports_counts, "Distribución de Puertos Destino", ports_plot)
        story.append(Image(ports_plot, width=400, height=250))
        story.append(Spacer(1, 16))

    # 4.5 Distribución de protocolos (RAW)
    proto_dist = _safe_dict(raw_summary.get("protocol_distribution"))
    if proto_dist:
        proto_labels = list(proto_dist.keys())
        proto_counts = list(proto_dist.values())
        proto_plot = os.path.join(plots_dir, "protocol_dist.png")
        _plot_bar(proto_labels, proto_counts, "Distribución de Protocolos (RAW)", proto_plot, rotation=0)
        story.append(Image(proto_plot, width=400, height=250))
        story.append(Spacer(1, 16))

    # 4.6 Resumen de flags TCP (RAW)
    flags = _safe_dict(raw_summary.get("flags_summary"))
    if flags:
        flag_labels = list(flags.keys())
        flag_counts = list(flags.values())
        flags_plot = os.path.join(plots_dir, "tcp_flags.png")
        _plot_bar(flag_labels, flag_counts, "Conteo Flags TCP (RAW)", flags_plot, rotation=0)
        story.append(Image(flags_plot, width=400, height=250))
        story.append(Spacer(1, 16))

    # === 5) Construir PDF ===
    doc.build(story)
    print(f"[✔] Reporte PDF generado en {output_pdf}")