// PWA Service Worker Registration
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/static/js/service-worker.js')
      .then((registration) => {
        console.log('Service Worker registered with scope:', registration.scope);
      })
      .catch((error) => {
        console.error('Service Worker registration failed:', error);
      });
  });

  // Add to Home Screen prompt handling
  let deferredPrompt;
  const addBtn = document.querySelector('.add-to-home');
  
  if (addBtn) {
    // Initially hide the button
    addBtn.style.display = 'none';
    
    window.addEventListener('beforeinstallprompt', (e) => {
      // Prevent Chrome 67 and earlier from automatically showing the prompt
      e.preventDefault();
      // Store the event so it can be triggered later
      deferredPrompt = e;
      // Show the button
      addBtn.style.display = 'block';
      
      addBtn.addEventListener('click', () => {
        // Hide the button as it's no longer needed
        addBtn.style.display = 'none';
        // Show the install prompt
        deferredPrompt.prompt();
        // Wait for the user to respond to the prompt
        deferredPrompt.userChoice.then((choiceResult) => {
          if (choiceResult.outcome === 'accepted') {
            console.log('User accepted the install prompt');
          } else {
            console.log('User dismissed the install prompt');
          }
          // Clear the saved prompt
          deferredPrompt = null;
        });
      });
    });
  }

  // Handle app installed event
  window.addEventListener('appinstalled', (evt) => {
    console.log('Application was installed');
  });
}