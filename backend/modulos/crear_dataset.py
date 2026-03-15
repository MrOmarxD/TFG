import pandas as pd
import os
import requests
from dotenv import load_dotenv
import json
import time
from groq import Groq

# CONFIGURACIÓN
load_dotenv()
api_key = os.getenv("GROQ_API_KEY")

# 2. Nombre del archivo que te bajaste de Kaggle
ARCHIVO_KAGGLE = "phishing_email.csv" 

# 3. Archivo final que le daremos a Google Colab
ARCHIVO_SALIDA = "dataset_entrenamiento_tfg.csv"

# Inicializamos el cliente de IA (Asegurándonos de pasarle la key)
cliente_ia = Groq(api_key=api_key)

# 1. LEER Y MUESTREAR EL DATASET DE KAGGLE
print("Leyendo el dataset gigante de Kaggle...")
df_completo = pd.read_csv(ARCHIVO_KAGGLE)
print("Las columnas del CSV son:", df_completo.columns.tolist())

# Extraemos una muestra balanceada
MUESTRAS_POR_CLASE = 500 

# CAMBIO: Usamos 'label' en lugar de 'Email Type'. Asumimos 1=Phishing, 0=Seguro
df_phishing = df_completo[df_completo['label'] == 1].sample(n=MUESTRAS_POR_CLASE, random_state=42)
df_seguro = df_completo[df_completo['label'] == 0].sample(n=MUESTRAS_POR_CLASE, random_state=42)

# Juntamos y mezclamos
df_muestra = pd.concat([df_phishing, df_seguro]).sample(frac=1).reset_index(drop=True)
print(f"Muestra creada con {len(df_muestra)} correos.")

# 2. EL PROMPT MAESTRO (La instrucción para la IA)
PROMPT_SISTEMA = """
Eres un analista experto en ciberseguridad. Voy a darte el texto de un correo electrónico.
Tu trabajo es analizarlo y devolver ÚNICAMENTE un objeto JSON válido con esta estructura exacta, sin texto adicional:
{
  "urgencia": true/false,
  "peticion_sensible": true/false,
  "intencion_detectada": "breve descripción de lo que busca el remitente",
  "categoria_texto": "phishing" o "seguro",
  "justificacion": "explicación en menos de 15 palabras"
}
"""

def analizar_correo_con_ia(texto_correo):
    try:
        # Llamamos al modelo Llama 3 70B
        respuesta = cliente_ia.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": PROMPT_SISTEMA},
                {"role": "user", "content": f"Analiza este correo:\n\n{texto_correo[:2000]}"} 
            ],
            temperature=0.1, 
            response_format={"type": "json_object"} 
        )
        return respuesta.choices[0].message.content
    except Exception as e:
        print(f"Error con la IA: {e}")
        return None

# 3. PROCESAR TODOS LOS CORREOS
resultados_json = []

print("Iniciando el etiquetado inteligente con Llama-3...")
for index, fila in df_muestra.iterrows():
    print(f"Analizando correo {index + 1}/{len(df_muestra)}...")
    
    # CAMBIO: Usamos 'text_combined' en lugar de 'Email Text'
    texto = str(fila['text_combined'])
    respuesta_json = analizar_correo_con_ia(texto)
    
    resultados_json.append(respuesta_json)
    
    # Pausa de 1 segundo para no saturar la API gratuita
    time.sleep(1)

# 4. GUARDAR EL RESULTADO FINAL
df_muestra['salida_esperada_json'] = resultados_json
df_muestra['instruccion_sistema'] = PROMPT_SISTEMA

# CAMBIO: Usamos 'text_combined' para guardar el archivo final
df_final = df_muestra[['instruccion_sistema', 'text_combined', 'salida_esperada_json']]
df_final.to_csv(ARCHIVO_SALIDA, index=False)

print(f"Dataset guardado como '{ARCHIVO_SALIDA}'")