# Detector de Phishing IA - TFG Deusto

Este repositorio contiene la Prueba de Concepto (PoC) del Trabajo de Fin de Grado en Ingeniería Informática centrado en la detección de correos corporativos fraudulentos y spear-phishing.

## Arquitectura del Proyecto

El proyecto sigue una arquitectura Cliente-Servidor separada en dos módulos:

* **Frontend (/frontend):** Add-in para Microsoft Outlook desarrollado con HTML, JS y la librería nativa "Office.js".
* **Backend ("/backend"):** API REST desarrollada en Python con **FastAPI**, encargada de orquestar el análisis de ciberseguridad.

## Motores de Análisis Integrados
* **Modelo NLP:** (En desarrollo) Análisis semántico del texto.
* **VirusTotal API:** Análisis de adjuntos maliciosos en múltiples motores antivirus.
* **Spamhaus:** Verificación DNS de dominios remitentes en listas negras.

## Cómo levantar el entorno de desarrollo

1.  Clonar el repositorio.
2.  Instalar las dependencias del backend:
    ```bash
    pip install -r requirements.txt
    ```
3.  Renombrar el archivo `.env.example` a `.env` y rellenar las API Keys.
4.  Lanzar el servidor local:
    ```bash
    uvicorn main:app --reload
    ```