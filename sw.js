/* 공유 받기 기능을 뺐습니다. 예전에 등록된 서비스 워커를 스스로 해제하고 공유 캐시를 지웁니다. 요청은 가로채지 않습니다. */
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil((async () => {
  try { await caches.delete('pf-share'); } catch {}
  await self.registration.unregister();
})()));
