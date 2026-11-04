import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import './index.css';
import App from './App.tsx';
import { wipeLegacyIdentity } from './crypto/identity.ts';

wipeLegacyIdentity();

// Here rather than inline in index.html, so the Content-Security-Policy can refuse inline scripts.
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js').catch(() => {});
  });
}

const root = document.getElementById('root');
if (!root) throw new Error('Root element not found');

// Errors can quote message content, so React's default of logging them to the console stays off.
createRoot(root, { onCaughtError: () => {}, onUncaughtError: () => {} }).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
