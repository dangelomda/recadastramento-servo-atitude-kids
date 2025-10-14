// Uma versão para ajudar na depuração e forçar a atualização
const SW_VERSION = 'v3';

// Força o novo Service Worker a assumir o controle imediatamente
self.addEventListener('install', () => {
  self.skipWaiting();
  console.log('Service Worker: Instalado (versão ' + SW_VERSION + ')');
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
  console.log('Service Worker: Ativado (versão ' + SW_VERSION + ')');
});

// Manipulador de Push robusto, com tratamento de erro
self.addEventListener('push', (e) => {
  console.log('Service Worker: Push Recebido.');
  let data = {};
  try {
    // Tenta interpretar os dados como JSON
    data = e.data ? e.data.json() : {};
  } catch (error) {
    // Se falhar, trata como texto simples
    console.error('Falha ao parsear payload do push como JSON:', error);
    data = { title: 'Notificação', body: e.data && e.data.text ? e.data.text() : 'Você recebeu uma nova notificação.' };
  }

  const title = data.title || 'Atitude Kids';
  const body  = data.body  || 'Você tem uma nova mensagem.';
  const icon  = '/public/logo.svg';

  // Garante que o Service Worker continue rodando até a notificação ser exibida
  e.waitUntil(self.registration.showNotification(title, { body, icon }));
});