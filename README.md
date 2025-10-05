# 🛰️ PaketIQ

PaketIQ es una herramienta de análisis de tráfico en PCAP que utiliza *Machine Learning* para clasificar automáticamente distintos tipos de tráfico y ataques de red, generando además un reporte en PDF.

---

## 🎯 Propósito

El objetivo principal de *PaketIQ* es facilitar la inspección de tráfico de red y la identificación de posibles ataques.
El sistema clasifica automáticamente entre diferentes etiquetas como:

* 🟢 *BENIGN*
* 🟠 *BOTNET-ARES*
* 🔐 *BRUTE-FORCE*
* 💣 *DoS-GOLDENEYE*
* 💥 *DoS-HULK*
* 🌐 *DDOS*
* 🐢 *DoS-SLOWHTTPTEST*
* 🕷️ *DoS-SLOWLORIS*
* 📡 *PORTSCAN*

Esto permite que analistas y profesionales de ciberseguridad tengan un apoyo automatizado para la toma de decisiones.

---

## 📊 Origen de los datos

El modelo fue entrenado con datasets públicos del *Canadian Institute for Cybersecurity (CIC), en particular el **CIC-IDS2017*, publicados en 2017.
También se complementó con *escenarios simulados en laboratorio* que generé para balancear las clases.

📌 Modelo utilizado: rt_model.pkl (ubicado en paketIQ/models/).

---

## ⚙️ Instalación

### 🔹 Paso 1: Clonar el repositorio

bash ~

git clone https://github.com/samuel1599gt/paketIQ.git

cd paketIQ


### 🔹 Paso 2: Crear entorno virtual

bash~

python3 -m venv .venv


### 🔹 Paso 3: Activar entorno

bash~ 

source .venv/bin/activate   # Linux/Mac
.venv\Scripts\activate      # Windows (PowerShell)


### 🔹 Paso 4: Instalar dependencias

bash~ 

pip install --upgrade pip
pip install -r requirements.txt


### 🔹 Paso 5: Seleccionar el intérprete en VS Code

1. Presiona *Ctrl + Shift + P* (o *Cmd + Shift + P* en macOS).
2. Escribe Python: Select Interpreter.
3. Elige el entorno *.venv* que creaste.

⚠️ Esto asegura que la terminal de VS Code use las librerías correctas y evita errores de "módulo no encontrado".

---

## 🖥️ Modo de uso (CLI)

Ejecuta el script principal indicando el archivo .pcap o .pcapng a analizar.

bash
python paketIQ.py archivo.pcap -o reporte.pdf -v


### 🔹 Parámetros disponibles:

* *pcap* → Argumento obligatorio. Ruta del archivo .pcap o .pcapng a analizar.
* *-o OUTPUT, --output OUTPUT* → Nombre del archivo PDF de salida.

  * Ejemplo: -o reporte.pdf
* *-v, --verbose* → Activa el modo detallado, mostrando más información durante la ejecución.
* *-h, --help* → Muestra el menú de ayuda y descripción de la herramienta.



## 📄 Ejemplo de reporte

Aquí puedes ver un ejemplo de reporte generado automáticamente por *PaketIQ*:  

👉 [Ver reporte en PDF](docs/reporte.pdf)

---

