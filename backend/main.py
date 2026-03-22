from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import logging

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

        # CAPA 2: VIRUSTOTAL - Evalúa los archivos adjuntos
        logger.info("-> Iniciando Capa 2: Análisis de Malware...")
        resultados_vt = []
        peligro_vt = False
        
        if data.tiene_adjuntos and data.adjuntos:
            logger.info(f"Procesando {len(data.adjuntos)} archivo(s) adjunto(s)...")
            primer_adjunto = data.adjuntos[0] # Para la PoC analizamos el primero
            res_vt = analizar_archivo_vt(primer_adjunto.nombre, primer_adjunto.contenido_base64)
            resultados_vt.append(res_vt)
            
            if res_vt.get("es_peligroso"):
                peligro_vt = True
        else:
            logger.info("El correo no tiene archivos adjuntos.")

        # CAPA 3: INTELIGENCIA ARTIFICIAL LOCAL - Evalúa el texto
        logger.info("-> Iniciando Capa 3: Semántica y Phishing (Llama-3)...")
        texto_limpio = data.texto if data.texto else ""
        resultado_ia = analizar_texto_ia(texto_limpio)

        # EL JUEZ FINAL (Árbol de Decisión del Ensemble)
        logger.info("-> Calculando Veredicto Final...")
        
        # Variables de ayuda para la decisión
        es_phishing_ia = resultado_ia.get("categoria_texto") == "phishing" or (resultado_ia.get("urgencia") and resultado_ia.get("peticion_sensible"))
        es_spam_osint = resultado_osint.get("es_peligroso")

        # Reglas de negocio (Prioridad: Malware > Phishing > Spam > Seguro)
        if peligro_vt:
            veredicto_final = "MALWARE"
            nivel_confianza = 0.99
            detalles = "VirusTotal ha detectado firmas maliciosas en el archivo adjunto."
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
                "virustotal": resultados_vt,
                "ia": resultado_ia # Aquí mandamos el JSON de Llama-3 al frontend
            }
        }
        
        return respuesta

    except Exception as e:
        logger.error(f"Error crítico en la orquestación: {e}")
        raise HTTPException(status_code=500, detail=str(e))