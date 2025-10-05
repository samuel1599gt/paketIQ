import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib

# Cargar dataset balanceado
df = pd.read_csv("/home/samuel/paketIQ/data_model/datoslistosparaelmodelo_limpio.csv")

# Variables a ignorar
ignore_cols = ["Label", "Src IP", "Dst IP"]

# Separar features y etiquetas
X = df.drop(columns=ignore_cols)
y = df["Label"]

# Dividir train/test
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Entrenar modelo (ejemplo RandomForest)
clf = RandomForestClassifier(
    n_estimators=200,  # más árboles que el default
    random_state=42,
    n_jobs=-1          # usa todos los núcleos disponibles
)
clf.fit(X_train, y_train)

# Evaluación
y_pred = clf.predict(X_test)
print("Reporte de métricas:")
print(classification_report(y_test, y_pred))

# Guardar modelo
joblib.dump(clf, "models/rf_model.pkl")
print("Modelo guardado en models/rf_model.pkl")