import logging
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
import os
from dotenv import load_dotenv
from modulos.spamhaus import verificar_dominio

# Cargar variables de entorno (.env)
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

# Modelo de Datos (Lo que esperamos recibir de Outlook)
class EmailData(BaseModel):
    texto: str
    remitente: Optional[str] = None
    tiene_adjuntos: Optional[bool] = False

@app.post("/api/v1/analizar")
async def analizar_correo(data: EmailData):
    logger.info("--------------------------------------------------")
    logger.info(f"Nueva solicitud de análisis recibida.")
    
    if not data.texto or len(data.texto.strip()) == 0:
        raise HTTPException(status_code=400, detail="El cuerpo del correo está vacío.")

    try:
        remitente_real = data.remitente if data.remitente else "Desconocido"
        logger.info(f"Remitente: {remitente_real}")
        
        resultado_spamhaus = verificar_dominio(remitente_real)
        
        # --- AQUÍ INTEGRAREMOS VIRUSTOTAL Y LA IA PRÓXIMAMENTE ---
        
        # Construimos el veredicto basándonos (por ahora) solo en Spamhaus
        veredicto = "PELIGROSO" if resultado_spamhaus["es_peligroso"] else "SEGURO"
        
        # Respuesta estructurada enviada de vuelta a Outlook
        respuesta = {
            "status": "success",
            "resultados": {
                "veredicto": veredicto,
                "confianza": 0.99 if resultado_spamhaus["es_peligroso"] else 0.50, # 99% si está en lista negra
                "detalles": resultado_spamhaus["detalle"]
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