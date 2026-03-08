import dns.resolver
import logging

logger = logging.getLogger(__name__)

def verificar_dominio(email: str) -> dict:
    """
    Comprueba si el dominio del email remitente está en la lista negra de Spamhaus (DBL).
    """
    if not email or "@" not in email:
        return {"es_peligroso": False, "detalle": "Remitente inválido o no detectado"}

    # Extraemos el dominio (ej: "hacker@estafa.com" -> "estafa.com")
    dominio = email.split("@")[1].strip()
    
    # Construimos la URL de consulta (ej: "estafa.com.dbl.spamhaus.org")
    query = f"{dominio}.dbl.spamhaus.org"

    try:
        logger.info(f"Consultando Spamhaus para el dominio: {dominio}...")
        
        # Hacemos una consulta DNS de tipo 'A'
        respuesta = dns.resolver.resolve(query, 'A')
        
        # Si Spamhaus devuelve una IP (suele ser 127.0.1.x), significa que ESTÁ en la lista negra
        if respuesta:
            logger.warning(f"¡ALERTA! El dominio {dominio} está en la lista negra de Spamhaus.")
            return {
                "es_peligroso": True, 
                "detalle": f"El dominio '{dominio}' está clasificado como malicioso por Spamhaus."
            }

    except dns.resolver.NXDOMAIN:
        # NXDOMAIN significa "No existe". En este contexto, es BUENO. 
        # Significa que Spamhaus no lo tiene en su lista negra.
        logger.info(f"El dominio {dominio} está limpio según Spamhaus.")
        return {
            "es_peligroso": False, 
            "detalle": "Dominio verificado, no se encuentra en listas negras."
        }
    except Exception as e:
        logger.error(f"Error al consultar Spamhaus: {e}")
        return {
            "es_peligroso": False, 
            "detalle": "No se pudo verificar el dominio con Spamhaus por un error de conexión."
        }