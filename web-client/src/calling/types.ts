// TypeScript mirrors of iOS PoolChat call protocol types.
// Byte-for-byte JSON-compatible with:
//   LocalPackages/PoolChat/Sources/Calling/Models/CallSignal.swift
//   LocalPackages/PoolChat/Sources/Calling/Models/MediaFrame.swift

export type CallSignalType =
  | 'offer'
  | 'answer'
  | 'reject'
  | 'end'
  | 'busy'
  | 'media_control'
  | 'request_keyframe';

export type CallMediaType = 'audio' | 'video';

export type CallEndReason =
  | 'normal'
  | 'rejected'
  | 'busy'
  | 'timeout'
  | 'error'
  | 'peer_disconnected';

/** Inner payload of a `media_control` signal. */
export type MediaControlPayload = {
  audioMuted: boolean;
  videoEnabled: boolean;
  requestKeyframe: boolean;
};

/**
 * Swift `JSONEncoder` default `dateEncodingStrategy = .deferredToDate` writes
 * `Date` as a Double of seconds since the Apple reference date
 * (2001-01-01 00:00:00 UTC = Unix epoch 978_307_200).
 *
 * Use `appleTimestampNow()` to produce the right value.
 */
export type CallSignal = {
  callID: string; // UUID, lowercase
  signalType: CallSignalType;
  callerPeerID: string;
  callerDisplayName: string;
  calleePeerIDs: string[];
  isVideoCall: boolean;
  /** Seconds since 2001-01-01 UTC, fractional. iOS-compat Date. */
  timestamp: number;
  mediaControl: MediaControlPayload | null;
};

/** Seconds since the Apple reference date (matches iOS `Date()` default encoding). */
export const APPLE_EPOCH_UNIX_SECONDS = 978_307_200;
export function appleTimestampNow(): number {
  return Date.now() / 1000 - APPLE_EPOCH_UNIX_SECONDS;
}

/**
 * Header for a single media frame on the wire. Same JSON shape as the iOS
 * `MediaFrameHeader` struct.
 */
export type MediaFrameHeader = {
  callID: string; // UUID, lowercase
  senderPeerID: string;
  mediaType: CallMediaType;
  /** UInt32, monotonically increasing per (sender, mediaType) per call. */
  sequence: number;
  /** UInt32. RTP-style: 16 kHz clock for audio, 90 kHz for video. */
  timestamp: number;
  /** Big-endian wire byte; UInt8. Always 0 for unfragmented. */
  fragmentIndex: number;
  /** UInt8. 1 = unfragmented. */
  totalFragments: number;
  /** Always false for audio. */
  isKeyFrame: boolean;
};

/** Audio constants matching iOS `AudioCallService`. */
export const AUDIO = {
  sampleRate: 16_000,
  frameMs: 20,
  samplesPerFrame: 320, // 16_000 * 0.020
  channels: 1,
} as const;

/** Video constants matching iOS `VideoCallService`. */
export const VIDEO = {
  fps: 15,
  width: 640,
  height: 480,
  bitrate: 300_000,
  keyframeInterval: 30, // every 2 s at 15 fps
  /** RTP-style 90 kHz clock for video frame timestamps. */
  clockHz: 90_000,
} as const;

/** Maximum codec payload bytes per fragment (matches iOS `MediaFrameCodec`). */
export const MAX_FRAGMENT_PAYLOAD_BYTES = 16_000;
