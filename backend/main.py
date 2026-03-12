import logging
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
import os
from dotenv import load_dotenv
from modulos.spamhaus import verificar_dominio
from modulos.virustotal import analizar_archivo_vt

# Cargar variables de entorno
load_dotenv()

# Configurar Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

# Inicializar la API
app = FastAPI(
    title="Detector de Phishing IA - TFG Deusto",
    description="API para el análisis de correos corporativos",
    version="1.0.0"
)

# Configurar CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class Adjunto(BaseModel):
    nombre: str
    contenido_base64: str

# Modelo de Datos (Lo que esperamos recibir de Outlook)
class EmailData(BaseModel):
    texto: str
    remitente: Optional[str] = None
    tiene_adjuntos: Optional[bool] = False
    adjuntos: Optional[List[Adjunto]] = []

@app.post("/api/v1/analizar")
async def analizar_correo(data: EmailData):
    logger.info("--------------------------------------------------")
    logger.info(f"Nueva solicitud de análisis recibida.")
    
    if not data.texto or len(data.texto.strip()) == 0:
        raise HTTPException(status_code=400, detail="El cuerpo del correo está vacío.")

    try:
        remitente_real = data.remitente if data.remitente else "Desconocido"
        logger.info(f"Remitente: {remitente_real}")
        
        # CAPA 2: SPAMHAUS
        resultado_spamhaus = verificar_dominio(remitente_real)

        # CAPA 2: VIRUSTOTAL
        resultados_vt = []
        peligro_vt = False # Variable para saber si VT detectó un virus
        
        if data.tiene_adjuntos and data.adjuntos:
            logger.info(f"Procesando {len(data.adjuntos)} archivo(s) adjunto(s)...")
            primer_adjunto = data.adjuntos[0]
            res_vt = analizar_archivo_vt(primer_adjunto.nombre, primer_adjunto.contenido_base64)
            resultados_vt.append(res_vt)
            
            # Si VT dice que es peligroso, marcamos la bandera
            if res_vt.get("es_peligroso"):
                peligro_vt = True
        else:
            logger.info("El correo no tiene archivos adjuntos.")
        
        # CALCULAMOS EL VEREDICTO FINAL
        # Es peligroso si Spamhaus lo bloquea O si VirusTotal encuentra malware
        es_peligroso_final = resultado_spamhaus.get("es_peligroso") or peligro_vt
        nivel_confianza = 0.99 if es_peligroso_final else 0.50

        # --- CONSTRUIMOS LA RESPUESTA ---
        respuesta = {
            "status": "success",
            "resultados": {
                "veredicto": "PELIGROSO" if es_peligroso_final else "SEGURO",
                "confianza": nivel_confianza,
                "spamhaus": resultado_spamhaus,
                "virustotal": resultados_vt,
                "detalles": "Análisis completado en múltiples capas."
            }
        }

        # Calculamos la confianza
        nivel_confianza = 0.99 if resultado_spamhaus.get("es_peligroso") else 0.50

        
        # Respuesta estructurada enviada de vuelta a Outlook
        respuesta = {
            "status": "success",
            "resultados": {
                "veredicto": "PELIGROSO" if resultado_spamhaus.get("es_peligroso") else "SEGURO",
                "confianza": nivel_confianza,
                "spamhaus": resultado_spamhaus,
                "virustotal": resultados_vt,
                "detalles": "Análisis completado en múltiples capas."
            }
        }
        
        logger.info("Análisis completado.")
        return respuesta

    except Exception as e:
        logger.error(f"Error crítico: {str(e)}")
        raise HTTPException(status_code=500, detail="Error interno procesando el correo.")

# Bloque para arrancar el servidor directamente desde el script
if __name__ == "__main__":
    import uvicorn
    puerto = int(os.getenv("PUERTO", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=puerto, reload=True)