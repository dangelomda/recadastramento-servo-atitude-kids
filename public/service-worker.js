console.log('Service Worker Carregado');

self.addEventListener('push', e => {
    const data = e.data.json();
    console.log('Push Recebido...', data);
    self.registration.showNotification(data.title, {
        body: data.body,
        icon: '/public/logo.svg' // Ícone que aparecerá na notificação
    });
});