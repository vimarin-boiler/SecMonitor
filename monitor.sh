#!/bin/bash
#
# Script para ejecutar una aplicación Python en Rocky Linux 10
# Autor: (tu nombre si quieres)
# Uso: ./ejecutar_app_python.sh
#

### === CONFIGURACIÓN === ###
PYTHON_BIN="/usr/bin/python3"        # Ruta del binario de Python
APP_DIR="/home/boiler/monitor"         # Carpeta donde está tu aplicación
APP_MAIN="main.py"                    # Script principal Python
VENV_PATH="$APP_DIR/.venv"            # Ruta del entorno virtual (si lo usas)

### === COMPROBAR PYTHON === ###
if [ ! -x "$PYTHON_BIN" ]; then
    echo "❌ ERROR: Python no encontrado en: $PYTHON_BIN"
    exit 1
fi

### === COMPROBAR DIRECTORIO === ###
if [ ! -d "$APP_DIR" ]; then
    echo "❌ ERROR: El directorio de la aplicación no existe: $APP_DIR"
    exit 1
fi

cd "$APP_DIR" || exit 1

### === ACTIVAR ENTORNO VIRTUAL (SI EXISTE) === ###
if [ -d "$VENV_PATH" ]; then
    echo "🔹 Activando entorno virtual..."
    source "$VENV_PATH/bin/activate"
else
    echo "⚠️ Advertencia: No se encontró entorno virtual. Usando Python del sistema."
fi

### === EJECUTAR APLICACIÓN === ###
echo "🚀 Ejecutando aplicación Python..."
$PYTHON_BIN "$APP_DIR/$APP_MAIN"

STATUS=$?

if [ $STATUS -eq 0 ]; then
    echo "✔️ La aplicación terminó correctamente."
else
    echo "❌ La aplicación terminó con errores. Código: $STATUS"
fi

exit $STATUS
