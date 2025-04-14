// Service Worker for IaM-Alliance Vetting System PWA
const CACHE_NAME = 'iam-alliance-cache-v1';
const ASSETS_TO_CACHE = [
  '/',
  '/login',
  '/static/css/custom.css',
  '/static/css/token-animations.css',
  '/static/js/main.js',
  '/static/libs/bootstrap/dist/bootstrap.bundle.min.js',
  '/static/libs/bootstrap/dist/bootstrap.min.css',
  '/static/libs/jquery/jquery-3.6.0.min.js',
  '/static/libs/fontawesome/css/all.min.css',
  '/static/icons/icon-192x192.png',
  '/static/icons/icon-512x512.png',
  '/static/libs/replit/bootstrap-agent-dark-theme.min.css'
];

// Install event - cache assets
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => {
        console.log('Opened cache');
        return cache.addAll(ASSETS_TO_CACHE);
      })
      .catch(error => {
        console.error('Service worker installation failed:', error);
      })
  );
  self.skipWaiting();
});

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames.map((cacheName) => {
          if (cacheName !== CACHE_NAME) {
            console.log('Deleting old cache:', cacheName);
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
  self.clients.claim();
});

// Fetch event - serve from cache if available, otherwise fetch from network
self.addEventListener('fetch', (event) => {
  // Skip cross-origin requests and certain API calls that shouldn't be cached
  if (
    !event.request.url.startsWith(self.location.origin) ||
    event.request.url.includes('/api/') ||
    event.request.method !== 'GET'
  ) {
    return;
  }

  event.respondWith(
    caches.match(event.request)
      .then((cachedResponse) => {
        if (cachedResponse) {
          return cachedResponse;
        }
        
        return fetch(event.request)
          .then((response) => {
            // Don't cache non-successful responses
            if (!response || response.status !== 200 || response.type !== 'basic') {
              return response;
            }

            // Clone the response - one to return, one to cache
            const responseToCache = response.clone();
            caches.open(CACHE_NAME)
              .then((cache) => {
                cache.put(event.request, responseToCache);
              });

            return response;
          })
          .catch(() => {
            // If fetch fails (offline), try to serve the HTML for navigation requests
            if (event.request.mode === 'navigate') {
              return caches.match('/');
            }
            
            return null;
          });
      })
  );
});