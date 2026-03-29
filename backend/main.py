from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import logging
import os
import re
from dotenv import load_dotenv
from modulos.seguridad_email import analizar_spf_y_cabeceras

# Le decimos a Python que suba un nivel (..) desde donde está este archivo
ruta_env = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '.env'))
load_dotenv(ruta_env)

# Importar los 3 módulos
from modulos.blocklists import verificar_reputacion_total
from modulos.virustotal import analizar_archivo_vt
from modulos.modelo_ia import analizar_texto_ia

# Configuración de logs
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI(title="API Ciberseguridad TFG", version="1.0")

# Evitar bloqueos de CORS al llamar desde Outlook Web
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MODELOS DE DATOS (Lo que Outlook nos envía)
class Adjunto(BaseModel):
    nombre: str
    contenido_base64: str

class CorreoRequest(BaseModel):
    texto: str
    remitente: str
    tiene_adjuntos: bool
    adjuntos: Optional[List[Adjunto]] = []
    cabeceras: Optional[str] = ""

# EL ENDPOINT PRINCIPAL
@app.post("/api/v1/analizar")
async def analizar_correo(data: CorreoRequest):
    logger.info("==================================================")
    logger.info(f"NUEVO CORREO RECIBIDO DE: {data.remitente}")
    logger.info("==================================================")

    try:
        # CAPA 1: OSINT (Spamhaus, SpamCop, PSBL) - Evalúa el remitente
        logger.info("-> Iniciando Capa 1: OSINT...")
        remitente_real = data.remitente if data.remitente else "Desconocido"
        resultado_osint = verificar_reputacion_total(remitente_real)

        # CAPA 1.5: AUTENTICACIÓN (SPF / Spoofing)
        logger.info("-> Iniciando Capa 1.5: Análisis de Cabeceras, SPF, DKIM y DMARC...")
        cabeceras_raw = data.cabeceras if data.cabeceras else ""
        resultado_spf = analizar_spf_y_cabeceras(remitente_real, cabeceras_raw)

        # CAPA 2: VIRUSTOTAL - Evalúa los archivos adjuntos
        logger.info("-> Iniciando Capa 2: Análisis de Malware (Adjuntos y URLs)...")
        resultados_vt_archivos = []
        resultados_vt_urls = []
        peligro_vt = False
        
        # 2.A: Analizar Archivos
        if data.tiene_adjuntos and data.adjuntos:
            logger.info(f"Procesando {len(data.adjuntos)} archivo(s) adjunto(s)...")
            primer_adjunto = data.adjuntos[0] 
            res_vt = analizar_archivo_vt(primer_adjunto.nombre, primer_adjunto.contenido_base64)
            resultados_vt_archivos.append(res_vt)
            if res_vt.get("es_peligroso"):
                peligro_vt = True

        # 2.B: Buscar y Analizar URLs en el texto
        urls_encontradas = re.findall(r'(https?://[^\s]+)', texto_limpio)
        # Limpiamos las URLs por si atrapan algún punto o coma al final de la frase
        urls_encontradas = [u.rstrip('.,;>\'")') for u in urls_encontradas]
        
        # Filtramos repetidas y limitamos a 2 para no saturar la API gratuita de VT
        urls_a_analizar = list(set(urls_encontradas))[:2] 
        
        if urls_a_analizar:
            logger.info(f"Se detectaron {len(urls_a_analizar)} URL(s). Enviando a VirusTotal...")
            for enlace in urls_a_analizar:
                res_url = analizar_url_vt(enlace)
                resultados_vt_urls.append(res_url)
                if res_url.get("es_peligroso"):
                    peligro_vt = True

        # CAPA 3: INTELIGENCIA ARTIFICIAL LOCAL - Evalúa el texto
        logger.info("-> Iniciando Capa 3: Semántica y Phishing (Llama-3)...")
        texto_limpio = data.texto if data.texto else ""
        resultado_ia = analizar_texto_ia(texto_limpio)

        # EL JUEZ FINAL (Árbol de Decisión del Ensemble)
        logger.info("-> Calculando Veredicto Final...")
        
        # Variables de ayuda para la decisión
        es_phishing_ia = resultado_ia.get("categoria_texto") == "phishing" or (resultado_ia.get("urgencia") and resultado_ia.get("peticion_sensible"))
        es_spam_osint = resultado_osint.get("es_peligroso")
        es_spoofing = resultado_spf.get("es_peligroso")

        # Reglas de negocio (Prioridad: Malware > Phishing > Spam > Seguro)
        if peligro_vt:
            veredicto_final = "MALWARE"
            nivel_confianza = 0.99
            detalles = "VirusTotal ha detectado firmas maliciosas en el archivo adjunto."
        elif es_spoofing:
            veredicto_final = "PHISHING (SPOOFING)"
            nivel_confianza = 0.99
            detalles = "ALERTA: El remitente ha falsificado la dirección de correo. El SPF ha fallado."
        elif es_phishing_ia:
            veredicto_final = "PHISHING"
            nivel_confianza = 0.95
            detalles = f"La IA detectó un intento de fraude: {resultado_ia.get('justificacion', 'Petición sospechosa')}"
        elif es_spam_osint:
            veredicto_final = "SPAM"
            nivel_confianza = 0.90
            detalles = "El dominio o IP del remitente se encuentra en listas negras."
        else:
            veredicto_final = "SEGURO"
            nivel_confianza = 0.98
            detalles = "El correo ha pasado los 3 filtros de seguridad sin levantar alertas."

        logger.info(f"VEREDICTO: {veredicto_final} (Confianza: {nivel_confianza})")

        # CONSTRUIMOS LA RESPUESTA PARA OUTLOOK
        respuesta = {
            "status": "success",
            "resultados": {
                "veredicto": veredicto_final,
                "confianza": nivel_confianza,
                "detalles": detalles,
                "osint": resultado_osint,
                "spf": resultado_spf,
                "virustotal": {"archivos": resultados_vt_archivos, "urls": resultados_vt_urls},
                "ia": resultado_ia
            }
        }
        
        return respuesta

    except Exception as e:
        logger.error(f"Error crítico en la orquestación: {e}")
        raise HTTPException(status_code=500, detail=str(e))