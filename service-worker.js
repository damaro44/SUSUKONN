const CACHE_NAME = 'susukonnect-mvp-v3';
const CORE_ASSETS = [
  './',
  './index.html',
  './manifest.json',
  './styles.css',
  './app.js',
  './assets/susukonnect-mark.svg',
  './assets/susukonnect-logo.svg'
];

// Install event - cache resources
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('Service Worker: Cache opened');
        return cache.addAll(CORE_ASSETS);
      })
      .catch(err => {
        console.log('Service Worker: Cache failed', err);
      })
  );
  self.skipWaiting();
});

// Activate event - clean up old caches
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cacheName => {
          if (cacheName !== CACHE_NAME) {
            console.log('Service Worker: Deleting old cache:', cacheName);
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
  self.clients.claim();
});

function isCoreRequest(request) {
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) {
    return false;
  }
  const path = url.pathname;
  return (
    path.endsWith('/') ||
    path.endsWith('/index.html') ||
    path.endsWith('/app.js') ||
    path.endsWith('/styles.css') ||
    path.endsWith('/manifest.json')
  );
}

// Fetch event - network-first for app shell assets, cache-first for others
self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET') {
    return;
  }

  const useNetworkFirst = isCoreRequest(event.request);
  event.respondWith(
    (useNetworkFirst
      ? fetch(event.request)
          .then(response => {
            if (!response || response.status !== 200 || response.type === 'error') {
              return caches.match(event.request).then(cached => cached || response);
            }
            const responseToCache = response.clone();
            caches.open(CACHE_NAME).then(cache => {
              cache.put(event.request, responseToCache);
            });
            return response;
          })
          .catch(() =>
            caches.match(event.request).then(
              cached => cached || new Response('Offline - SusuKonnect cannot reach network right now.')
            )
          )
      : caches.match(event.request).then(cached => {
          if (cached) {
            return cached;
          }
          return fetch(event.request)
            .then(response => {
              if (!response || response.status !== 200 || response.type === 'error') {
                return response;
              }
              const responseToCache = response.clone();
              caches.open(CACHE_NAME).then(cache => {
                cache.put(event.request, responseToCache);
              });
              return response;
            })
            .catch(() =>
              caches.match(event.request).then(
                fallback => fallback || new Response('Offline - SusuKonnect cannot reach network right now.')
              )
            );
        }))
  );
});

// Handle messages from clients
self.addEventListener('message', event => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

console.log('Service Worker: Registered successfully');
