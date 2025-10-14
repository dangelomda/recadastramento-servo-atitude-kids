const VAPID_PUBLIC_KEY = 'BM8a5G7bpGHzTlB-ywsqY1_hsmWw7GesrSeRpGQPxFZLNTttpdjUi1SAhu0OvUYuUdNEdRwJs2W9rEp6HQtkxGk';

// Função para converter a chave VAPID
function urlBase64ToUint8Array(base64String) {
    const padding = '='.repeat((4 - base64String.length % 4) % 4);
    const base64 = (base64String + padding).replace(/\-/g, '+').replace(/_/g, '/');
    const rawData = window.atob(base64);
    const outputArray = new Uint8Array(rawData.length);
    for (let i = 0; i < rawData.length; ++i) {
        outputArray[i] = rawData.charCodeAt(i);
    }
    return outputArray;
}

// Verifica se o navegador suporta notificações e service workers
if ('serviceWorker' in navigator && 'PushManager' in window) {
    console.log('Service Worker e Push são suportados');

    // Botão para pedir permissão (vamos criá-lo no HTML depois)
    const subscribeButton = document.getElementById('subscribe-button');
    if (subscribeButton) {
        subscribeButton.addEventListener('click', () => {
            navigator.serviceWorker.ready.then(registration => {
                registration.pushManager.subscribe({
                    userVisibleOnly: true,
                    applicationServerKey: urlBase64ToUint8Array(VAPID_PUBLIC_KEY)
                }).then(subscription => {
                    console.log('Usuário inscrito:', subscription);
                    // Envia a inscrição para o servidor
                    fetch('/meu/save-subscription', {
                        method: 'POST',
                        body: JSON.stringify(subscription),
                        headers: {
                            'Content-Type': 'application/json'
                        }
                    });
                    subscribeButton.textContent = 'Inscrito para notificações!';
                    subscribeButton.disabled = true;
                }).catch(err => {
                    console.error('Falha ao inscrever o usuário: ', err);
                });
            });
        });
    }

    // Registra o Service Worker
    navigator.serviceWorker.register('/service-worker.js')
        .then(swReg => {
            console.log('Service Worker registrado', swReg);
        })
        .catch(error => {
            console.error('Erro ao registrar Service Worker', error);
        });
} else {
    console.warn('Push messaging não é suportado');
}