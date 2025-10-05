import pandas as pd
import numpy as np

def group_flows(csv_path, output_path=None):
    """
    Agrupa flujos por Src IP y Dst IP y calcula métricas agregadas extendidas.
    """
    df = pd.read_csv(csv_path)

    aggregation = {
        'Total Packets': 'sum',
        'Total Length of Fwd Packets': 'sum',
        'Total Length of Bwd Packets': 'sum',
        'Subflow Fwd Bytes': 'sum',
        'Subflow Bwd Bytes': 'sum',
        'Subflow Fwd Packets': 'sum',
        'Subflow Bwd Packets': 'sum',
        'Avg Fwd Segment Size': 'mean',
        'Avg Bwd Segment Size': 'mean',
        'Fwd Packet Length Max': 'max',
        'Fwd Packet Length Min': 'min',
        'Fwd Packet Length Mean': 'mean',
        'Fwd Packet Length Std': 'mean',
        'Bwd Packet Length Max': 'max',
        'Bwd Packet Length Min': 'min',
        'Bwd Packet Length Mean': 'mean',
        'Bwd Packet Length Std': 'mean',
        'Average Packet Size': 'mean',
        'Flow Duration': 'sum',
        'Fwd IAT Mean': 'mean',
        'Fwd IAT Std': 'mean',
        'Fwd IAT Max': 'max',
        'Fwd IAT Min': 'min',
        'Fwd IAT Total': 'sum',
        'Bwd IAT Mean': 'mean',
        'Bwd IAT Std': 'mean',
        'Bwd IAT Max': 'max',
        'Bwd IAT Min': 'min',
        'Bwd IAT Total': 'sum',
        'SYN Flag Count': 'sum',
        'FIN Flag Count': 'sum',
        'RST Flag Count': 'sum',
        'PSH Flag Count': 'sum',
        'URG Flag Count': 'sum'
    }

    grouped = df.groupby(['Src IP', 'Dst IP']).agg(aggregation).reset_index()

    # Métricas adicionales
    grouped['Total Bytes'] = grouped['Subflow Fwd Bytes'] + grouped['Subflow Bwd Bytes']
    grouped['Packets/s'] = grouped['Total Packets'] / (grouped['Flow Duration'] / 1e6 + 1)
    grouped['Bytes/s'] = grouped['Total Bytes'] / (grouped['Flow Duration'] / 1e6 + 1)
    grouped['Packets Ratio Fwd/Bwd'] = (grouped['Subflow Fwd Packets'] + 1) / (grouped['Subflow Bwd Packets'] + 1)
    grouped['Bytes Ratio Fwd/Bwd'] = (grouped['Subflow Fwd Bytes'] + 1) / (grouped['Subflow Bwd Bytes'] + 1)
    grouped['Max Packet Size'] = grouped[['Fwd Packet Length Max', 'Bwd Packet Length Max']].max(axis=1)
    grouped['Min Packet Size'] = grouped[['Fwd Packet Length Min', 'Bwd Packet Length Min']].min(axis=1)

    if output_path:
        grouped.to_csv(output_path, index=False)
        print(f"[✔] CSV de flujos agrupados guardado en: {output_path}")

    return grouped