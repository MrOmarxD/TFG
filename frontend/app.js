const BACKEND_URL = "https://overintense-cleo-unwaved.ngrok-free.dev/api/v1/analizar";

Office.onReady((info) => {
    if (info.host === Office.HostType.Outlook) {
        document.getElementById("btn-analizar").addEventListener("click", orquestarAnalisis);
    }
});

async function orquestarAnalisis() {
    const btn = document.getElementById("btn-analizar");
    const consola = document.getElementById("consola");
    
    btn.disabled = true;
    btn.innerHTML = '<div class="spinner"></div> Procesando...';
    consola.style.display = "block";
    consola.innerHTML = "<i>1. Extrayendo metadatos de Outlook...</i>";

    try {
        // Extraer datos del correo
        const texto = await obtenerTextoAsync();
        const remitente = Office.context.mailbox.item.from.emailAddress;
        const tieneAdjuntos = Office.context.mailbox.item.attachments.length > 0;

        consola.innerHTML += "<br><i>2. Enviando datos al servidor seguro...</i>";

        // Petición al backend
        const respuesta = await fetch(BACKEND_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ 
                texto: texto,
                remitente: remitente,
                tiene_adjuntos: tieneAdjuntos
            })
        });

        if (!respuesta.ok) {
            throw new Error(`Error HTTP: ${respuesta.status}`);
        }

        const data = await respuesta.json();

        // Mostrar Resultado
        consola.style.borderLeftColor = "#107C10";
        consola.innerHTML = `
            <b>Análisis completado:</b><br><br>
            <b>Veredicto:</b> ${data.resultados.veredicto}<br>
            <b>Confianza:</b> ${data.resultados.confianza * 100}%<br>
            <hr style="border:0; border-top:1px solid #ddd;">
            <small>${data.resultados.detalles}</small>
        `;

    } catch (error) {
        console.error(error);
        consola.style.borderLeftColor = "#D83B01";
        consola.innerHTML = `<b>Error:</b> No se pudo completar el análisis.<br><small>${error.message}</small>`;
    } finally {
        btn.disabled = false;
        btn.innerHTML = "Analizar Correo";
    }
}

// Helper para convertir Office.js en Promesa
function obtenerTextoAsync() {
    return new Promise((resolve, reject) => {
        Office.context.mailbox.item.body.getAsync(Office.CoercionType.Text, (result) => {
            if (result.status === Office.AsyncResultStatus.Failed) {
                reject(new Error(result.error.message));
            } else {
                resolve(result.value);
            }
        });
    });
}