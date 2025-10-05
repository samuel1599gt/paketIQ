import pandas as pd
import joblib

class ModelLoader:
    def __init__(self, model_path="models/rf_model.pkl"):
        """Inicializa y carga el modelo entrenado"""
        self.model = joblib.load(model_path)

    def predict(self, X):
        """Predice etiquetas a partir de un DataFrame de features"""
        return self.model.predict(X)

    def predict_from_csv(self, csv_path, ignore_cols=None):
        """Carga un CSV, limpia columnas no necesarias y predice"""
        df = pd.read_csv(csv_path)

        if ignore_cols:
            X = df.drop(columns=[col for col in ignore_cols if col in df.columns])
        else:
            X = df

        preds = self.model.predict(X)
        df["Prediction"] = preds
        return df