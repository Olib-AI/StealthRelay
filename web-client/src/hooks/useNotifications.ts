const STORAGE_KEY = 'stealth_notifications';

export function isNotificationSupported(): boolean {
  return 'Notification' in window;
}

export function getNotificationPermission(): NotificationPermission | 'unsupported' {
  if (!isNotificationSupported()) return 'unsupported';
  return Notification.permission;
}

export function isNotificationEnabled(): boolean {
  return localStorage.getItem(STORAGE_KEY) === 'enabled';
}

export async function requestNotificationPermission(): Promise<boolean> {
  if (!isNotificationSupported()) return false;
  const result = await Notification.requestPermission();
  if (result === 'granted') {
    localStorage.setItem(STORAGE_KEY, 'enabled');
    return true;
  }
  return false;
}

export function disableNotifications(): void {
  localStorage.removeItem(STORAGE_KEY);
}

/**
 * A notification leaves this page for the OS, its history and the lock screen. So, as with the app's
 * background session, it carries no sender, no title and no content: just that something arrived.
 */
export function sendNotification(tag?: string): void {
  if (!isNotificationSupported() || Notification.permission !== 'granted' || !isNotificationEnabled()) return;
  // Don't notify if the page is focused
  if (document.hasFocus()) return;

  try {
    new Notification('StealthOS', {
      body: 'You have a new message.',
      icon: '/icons/icon-192.png',
      tag: tag ?? 'stealth-message',
    } as NotificationOptions);
  } catch {
    // Notification constructor may fail in some contexts
  }
}
