import argparse
import os
import shutil
import json

from modules.flow_extractor import extract_flow
from modules.preprocessor import preprocess_data
from modules.flow_grouper import group_flows
from modules.model_loader import ModelLoader
from modules.attack_interpreter import interpret_attacks
from modules.report_generator import generate_report


def get_downloads_folder():
    """
    Devuelve la carpeta de descargas disponible en el sistema.
    Prioridad:
      1. ~/Downloads
      2. ~/Descargas
      3. Crea ~/Downloads si ninguna existe
    """
    home = os.path.expanduser("~")
    downloads = os.path.join(home, "Downloads")
    descargas = os.path.join(home, "Descargas")

    if os.path.isdir(downloads):
        return downloads
    elif os.path.isdir(descargas):
        return descargas
    else:
        os.makedirs(downloads, exist_ok=True)
        return downloads


def main():
    # -----------------------------
    # 1. Configurar argumentos CLI
    # -----------------------------
    parser = argparse.ArgumentParser(
        description="Herramienta de análisis de tráfico en PCAP y generación de reportes PDF."
    )
    parser.add_argument(
        "pcap",
        type=str,
        help="Ruta del archivo .pcap o .pcapng a analizar."
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        required=True,
        help="Nombre del archivo PDF de salida (ejemplo: reporte.pdf)."
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Muestra información detallada durante la ejecución."
    )

    args = parser.parse_args()
    pcap_path = args.pcap
    pdf_name = args.output
    verbose = args.verbose

    # -----------------------------
    # 2. Definir rutas internas
    # -----------------------------
    base_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(base_dir, "data")
    input_dir = os.path.join(data_dir, "input")
    output_dir = os.path.join(data_dir, "output")

    os.makedirs(output_dir, exist_ok=True)

    # Carpeta de destino del PDF
    downloads_dir = get_downloads_folder()

    # Archivos temporales
    raw_csv_path = os.path.join(output_dir, "raw_flows.csv")
    grouped_csv_path = os.path.join(output_dir, "grouped_flows.csv")
    pred_csv_path = os.path.join(output_dir, "predicted_flows.csv")
    report_json_path = os.path.join(output_dir, "report.json")

    # PDF final
    pdf_path = os.path.join(downloads_dir, pdf_name)

    # -----------------------------
    # 3. Pipeline completo
    # -----------------------------
    print("[INFO] Analizando tráfico...")

    df_flows = extract_flow(pcap_path)
    preprocess_data(df_flows, output_dir=output_dir)

    df_grouped = group_flows(raw_csv_path, output_path=grouped_csv_path)

    IGNORE_COLS = ["Label", "Src IP", "Dst IP"]
    loader = ModelLoader("models/rf_model.pkl")

    df_pred = loader.predict_from_csv(grouped_csv_path, ignore_cols=IGNORE_COLS)
    df_pred.to_csv(pred_csv_path, index=False)

    report = interpret_attacks(
        predicted_csv=pred_csv_path,
        raw_csv=raw_csv_path,
        ratio_threshold=0.1,
        min_flows=100,
        export_json=report_json_path
    )

    if verbose:
        print(json.dumps(report, indent=4))

    print("[INFO] Generando reporte PDF final...")
    generate_report(report_json_path, pdf_path)
    print(f"[✔] Reporte PDF guardado en: {pdf_path}")

    # -----------------------------
    # 4. Limpieza de archivos temporales
    # -----------------------------
    shutil.rmtree(output_dir)
    os.makedirs(output_dir, exist_ok=True)

    plots_dir = os.path.join(base_dir, "plots_tmp")
    if os.path.exists(plots_dir):
        shutil.rmtree(plots_dir)

    if verbose:
        print("[✔] Archivos temporales eliminados.")

    print("[✔] Proceso completado.")


if __name__ == "__main__":
    main()
  