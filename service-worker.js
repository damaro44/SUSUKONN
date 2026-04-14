const CACHE_NAME = "eclair-tech-assistance-v1";
const CORE_ASSETS = [
  "./",
  "./index.html",
  "./manifest.json",
  "./styles.css",
  "./app.js",
  "./assets/susukonnect-mark.svg"
];

self.addEventListener("install", event => {
  event.waitUntil(
    caches
      .open(CACHE_NAME)
      .then(cache => cache.addAll(CORE_ASSETS))
      .catch(error => {
        console.error("Service Worker cache init failed", error);
      })
  );
  self.skipWaiting();
});

self.addEventListener("activate", event => {
  event.waitUntil(
    caches.keys().then(cacheNames =>
      Promise.all(
        cacheNames.map(name => {
          if (name !== CACHE_NAME) {
            return caches.delete(name);
          }
          return null;
        })
      )
    )
  );
  self.clients.claim();
});

self.addEventListener("fetch", event => {
  if (event.request.method !== "GET") {
    return;
  }

  const url = new URL(event.request.url);
  const sameOrigin = url.origin === self.location.origin;

  if (!sameOrigin) {
    return;
  }

  const shouldNetworkFirst = ["/", "/index.html", "/app.js", "/styles.css", "/manifest.json"].some(path =>
    url.pathname.endsWith(path)
  );

  event.respondWith(
    shouldNetworkFirst
      ? fetch(event.request)
          .then(response => {
            if (!response || response.status !== 200) {
              return caches.match(event.request).then(cached => cached || response);
            }
            const copy = response.clone();
            caches.open(CACHE_NAME).then(cache => cache.put(event.request, copy));
            return response;
          })
          .catch(() =>
            caches.match(event.request).then(
              cached =>
                cached ||
                new Response("Offline mode: Eclair Technology Assistance is serving cached data.")
            )
          )
      : caches.match(event.request).then(cached => {
          if (cached) {
            return cached;
          }

          return fetch(event.request)
            .then(response => {
              if (!response || response.status !== 200) {
                return response;
              }
              const copy = response.clone();
              caches.open(CACHE_NAME).then(cache => cache.put(event.request, copy));
              return response;
            })
            .catch(
              () =>
                new Response("Offline mode: requested asset is not cached yet.", {
                  status: 503,
                  statusText: "Service Unavailable"
                })
            );
        })
  );
});
