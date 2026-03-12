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
    btn.innerHTML = '<div class="spinner"></div> Analizando...';
    consola.style.display = "block";
    consola.innerHTML = "<i>1. Leyendo correo y adjuntos...</i>";

    try {
        const texto = await obtenerTextoAsync();
        const remitente = Office.context.mailbox.item.from.emailAddress;
        
        // LÓGICA DE ADJUNTOS
        const adjuntosOutlook = Office.context.mailbox.item.attachments;
        const tieneAdjuntos = adjuntosOutlook.length > 0;
        let listaAdjuntosParaPython = [];

        if (tieneAdjuntos) {
            consola.innerHTML += `<br><i>2. Extrayendo ${adjuntosOutlook.length} archivo(s) adjunto(s)...</i>`;
            // Extraemos solo el primero para la PoC
            const primerAdjunto = adjuntosOutlook[0];
            const contenidoBase64 = await obtenerAdjuntoBase64Async(primerAdjunto.id);
            
            listaAdjuntosParaPython.push({
                nombre: primerAdjunto.name,
                contenido_base64: contenidoBase64
            });
        }

        consola.innerHTML += "<br><i>3. Enviando datos a Python, Spamhaus y VirusTotal...</i>";

        const respuesta = await fetch(BACKEND_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ 
                texto: texto,
                remitente: remitente,
                tiene_adjuntos: tieneAdjuntos,
                adjuntos: listaAdjuntosParaPython
            })
        });

        if (!respuesta.ok) throw new Error(`Error HTTP: ${respuesta.status}`);
        const data = await respuesta.json();

        consola.style.borderLeftColor = data.resultados.veredicto === "PELIGROSO" ? "#D83B01" : "#107C10";
        // Lógica visual para pintar VirusTotal
        let htmlVT = "<br><b>VirusTotal:</b> Sin adjuntos.";
        
        if (data.resultados.virustotal.length > 0) {
            let vt = data.resultados.virustotal[0]; // Cogemos el primer adjunto
            
            if (vt.error) {
                htmlVT = `<br><b>VirusTotal:</b> ⚠️ Error de conexión.`;
            } else if (vt.analizado) {
                // Si ya se conoce el archivo, pintamos los motores
                let colorVT = vt.es_peligroso ? "#D83B01" : "#107C10";
                let icono = vt.es_peligroso ? "🔴" : "🟢";
                htmlVT = `<br><b>VirusTotal:</b> <span style="color:${colorVT}; font-weight:bold;">${icono} ${vt.maliciosos} / ${vt.total_motores} motores detectaron malware</span>`;
            } else {
                // Si es nuevo y se está subiendo
                htmlVT = `<br><b>VirusTotal:</b> ⏳ ${vt.mensaje}`;
            }
        }

        // Actualizamos la consola visual
        consola.innerHTML = `
            <b>Análisis completado:</b><br><br>
            <b>Veredicto Global:</b> ${data.resultados.veredicto}<br>
            <b>Confianza:</b> ${data.resultados.confianza * 100}%<br>
            <hr style="border:0; border-top:1px solid #ddd;">
            ${htmlVT}
        `;

    } catch (error) {
        console.error(error);
        consola.style.borderLeftColor = "#D83B01";
        consola.innerHTML = `<b>Error:</b> <small>${error.message}</small>`;
    } finally {
        btn.disabled = false;
        btn.innerHTML = "Analizar Correo";
    }
}

// Helper para extraer el texto
function obtenerTextoAsync() {
    return new Promise((resolve, reject) => {
        Office.context.mailbox.item.body.getAsync(Office.CoercionType.Text, (result) => {
            if (result.status === Office.AsyncResultStatus.Failed) reject(new Error(result.error.message));
            else resolve(result.value);
        });
    });
}

// Helper para extraer el archivo adjunto en Base64
function obtenerAdjuntoBase64Async(attachmentId) {
    return new Promise((resolve, reject) => {
        Office.context.mailbox.item.getAttachmentContentAsync(attachmentId, (result) => {
            if (result.status === Office.AsyncResultStatus.Failed) {
                reject(new Error(result.error.message));
            } else {
                // Office.js devuelve el formato y el contenido. Nos quedamos el contenido en base64.
                resolve(result.value.content);
            }
        });
    });
}