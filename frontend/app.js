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

        consola.innerHTML += "<br><i>3. Consultando OSINT y VirusTotal...</i>";

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

        // Color del borde general
        let colorVeredicto = data.resultados.veredicto === "PELIGROSO" ? "#D83B01" : "#107C10";
        consola.style.borderLeftColor = colorVeredicto;

        // LÓGICA VISUAL PARA LISTAS NEGRAS (OSINT)
        const osint = data.resultados.osint;
        const getIcon = (isListed) => isListed ? "🔴" : "🟢";
        const getColor = (isListed) => isListed ? "#D83B01" : "#107C10";

        let htmlOSINT = `
            <div style="margin-top: 15px; margin-bottom: 15px; padding: 10px; background: #fff; border: 1px solid #ddd; border-radius: 4px;">
                <b style="font-size: 12px; color: #555;">INTELIGENCIA DE AMENAZAS (IP/Dominio)</b><br>
                <span style="color: ${getColor(osint.spamhaus)};">${getIcon(osint.spamhaus)} Spamhaus DBL</span><br>
                <span style="color: ${getColor(osint.spamcop)};">${getIcon(osint.spamcop)} SpamCop</span><br>
                <span style="color: ${getColor(osint.psbl)};">${getIcon(osint.psbl)} PSBL</span>
            </div>
        `;

        // LÓGICA VISUAL PARA VIRUSTOTAL
        let htmlVT = "<br><b>VirusTotal:</b> Sin adjuntos.";
        if (data.resultados.virustotal.length > 0) {
            let vt = data.resultados.virustotal[0]; 
            
            if (vt.error) {
                htmlVT = `<br><b>VirusTotal:</b> ⚠️ Error de conexión.`;
            } else if (vt.analizado) {
                let colorVT = vt.es_peligroso ? "#D83B01" : "#107C10";
                let icono = vt.es_peligroso ? "🔴" : "🟢";
                htmlVT = `<br><b>VirusTotal:</b> <span style="color:${colorVT}; font-weight:bold;">${icono} ${vt.maliciosos} / ${vt.total_motores} motores detectaron malware</span>`;
            } else {
                htmlVT = `<br><b>VirusTotal:</b> ${vt.mensaje}`;
            }
        }

        // CONSTRUIR PANTALLA FINAL
        consola.innerHTML = `
            <b>Análisis completado:</b><br><br>
            <b>Veredicto Global:</b> <span style="font-weight:bold; color:${colorVeredicto};">${data.resultados.veredicto}</span><br>
            <b>Confianza:</b> ${data.resultados.confianza * 100}%<br>
            ${htmlOSINT}
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

function obtenerTextoAsync() {
    return new Promise((resolve, reject) => {
        Office.context.mailbox.item.body.getAsync(Office.CoercionType.Text, (result) => {
            if (result.status === Office.AsyncResultStatus.Failed) reject(new Error(result.error.message));
            else resolve(result.value);
        });
    });
}

function obtenerAdjuntoBase64Async(attachmentId) {
    return new Promise((resolve, reject) => {
        Office.context.mailbox.item.getAttachmentContentAsync(attachmentId, (result) => {
            if (result.status === Office.AsyncResultStatus.Failed) {
                reject(new Error(result.error.message));
            } else {
                resolve(result.value.content);
            }
        });
    });
}