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

export function sendNotification(title: string, body: string, tag?: string): void {
  if (!isNotificationSupported() || Notification.permission !== 'granted' || !isNotificationEnabled()) return;
  // Don't notify if the page is focused
  if (document.hasFocus()) return;

  try {
    new Notification(title, {
      body,
      icon: '/icons/icon-192.png',
      tag: tag ?? 'stealth-message',
    } as NotificationOptions);
  } catch {
    // Notification constructor may fail in some contexts
  }
}
