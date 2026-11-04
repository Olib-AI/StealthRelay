// A reply carries its own idea of what it quotes, and that can be anything. So, as in the app, what shows
// is this device's copy of the message it names, or that the original isn't here.

interface QuotableMessage {
  id: string;
  senderName: string;
  contentType: string;
  text?: string;
  emoji?: string;
}

export interface ResolvedReply {
  senderName: string;
  text: string;
}

function previewOf(message: QuotableMessage): string {
  if (message.text) return message.text;
  if (message.emoji) return message.emoji;
  switch (message.contentType) {
    case 'image':
      return 'Photo';
    case 'voice':
      return 'Voice message';
    case 'poll':
      return 'Poll';
    default:
      return 'Message';
  }
}

export function resolveReply(quote: { messageID: string }, messages: readonly QuotableMessage[]): ResolvedReply | null {
  const id = quote.messageID.toLowerCase();
  const message = messages.find((candidate) => candidate.id.toLowerCase() === id);
  return message ? { senderName: message.senderName, text: previewOf(message) } : null;
}
