import os
import pandas as pd

def preprocess_data(df, output_dir=""):
    """
    Preprocesa el DataFrame de flujos y guarda:
    1. raw_flows.csv → dataset completo con todas las métricas y columnas de reporte
    2. dataset_for_model.csv → solo las features del modelo (SIN escalado)
    
    Esta versión es flexible: si alguna columna no existe, se omite y se genera un warning.
    """

    os.makedirs(output_dir, exist_ok=True)

    # Guardar dataset completo para reporte
    report_path = os.path.join(output_dir, "raw_flows.csv")
    df.to_csv(report_path, index=False)
    
    # Features que usa el modelo
    model_features = [
        "Fwd Packet Length Max",
        "Init_Win_bytes_forward",
        "Subflow Fwd Bytes",
        "Fwd Packet Length Mean",
        "Subflow Fwd Packets",
        "Avg Fwd Segment Size",
        "Destination Port",
        "Bwd Packet Length Min",
        "Total Length of Fwd Packets",
        "act_data_pkt_fwd",
        "Fwd IAT Std",
        "Fwd IAT Max",
        "Fwd IAT Total",
        "Fwd IAT Mean",
        "Fwd Header Length",
        "Fwd Header Length.1",
        "Bwd Packet Length Max",
        "Bwd IAT Max",
        "Average Packet Size",
        "Init_Win_bytes_backward",
        "Fwd Packet Length Std",
        "Total Fwd Packets",
        "Avg Bwd Segment Size",
        "Bwd IAT Total",
        "Subflow Bwd Packets"
    ]

    # Detectar columnas faltantes
    missing = [col for col in model_features if col not in df.columns]
    if missing:
        print(f"Faltan columnas para el modelo, se omiten: {missing}")

    # Seleccionar solo las columnas que existen
    available_features = [col for col in model_features if col in df.columns]
    df_model = df[available_features].copy()

    model_path = os.path.join(output_dir, "dataset_for_model.csv")
    df_model.to_csv(model_path, index=False)
    return df_model, df