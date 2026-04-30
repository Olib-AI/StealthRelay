// Call lifecycle and media-frame router. Mirrors the iOS `CallManager`.
//
// Three responsibilities:
//   1. State machine: idle → outgoing/incoming → active → ending → idle.
//   2. Signal dispatch: serialize `CallSignal` JSON, hand to a sender callback.
//   3. Media-frame ingress: take inbound decrypted `MediaFrameHeader+payload`
//      and route to the audio (or video) playback path keyed by peer.

import { v4 as uuidv4 } from 'uuid';
import {
  type CallSignal,
  type CallSignalType,
  type CallEndReason,
  type MediaControlPayload,
  type MediaFrameHeader,
  AUDIO,
  appleTimestampNow,
} from './types.ts';
import { fragmentFrame, FragmentReassembler, unpackFrame } from './frame-codec.ts';
import { startAudioCapture, type AudioCapture } from './audio-capture.ts';
import { AudioPlayback } from './audio-playback.ts';
import { startVideoCapture, type VideoCapture } from './video-capture.ts';
import { VideoPlayback } from './video-playback.ts';
import { VIDEO } from './types.ts';

export type CallState = 'idle' | 'outgoing' | 'incoming' | 'active' | 'ending';

export type ActiveCall = {
  callID: string;
  state: CallState;
  isInitiator: boolean;
  isVideoCall: boolean;
  remotePeerIDs: string[];
  remoteDisplayName: string;
  startedAt: number | null;
  audioMuted: boolean;
  videoEnabled: boolean;
  remoteAudioMuted: Record<string, boolean>;
  remoteVideoEnabled: Record<string, boolean>;
};

export type CallManagerDelegate = {
  sendSignal: (signal: CallSignal, peerIDs: string[]) => void;
  /** Called once per fragment, per recipient. Implementer encrypts + transports. */
  sendMediaFrame: (frame: Uint8Array, peerIDs: string[], reliable: boolean) => void;
  onStateChange: (call: ActiveCall | null) => void;
  onError: (message: string) => void;
};

const RING_TIMEOUT_MS = 45_000;
const CONNECT_TIMEOUT_MS = 15_000;

export class CallManager {
  private call: ActiveCall | null = null;
  private localPeerID: string;
  private localDisplayName: string;
  private delegate: CallManagerDelegate;

  private audioCapture: AudioCapture | null = null;
  private playbackByPeer = new Map<string, AudioPlayback>();
  private audioReassemblers = new Map<string, FragmentReassembler>();

  private videoCapture: VideoCapture | null = null;
  private videoPlaybackByPeer = new Map<string, VideoPlayback>();
  private videoReassemblers = new Map<string, FragmentReassembler>();

  private audioSequence = 0;
  private ringTimer: number | null = null;
  private connectTimer: number | null = null;

  constructor(args: {
    localPeerID: string;
    localDisplayName: string;
    delegate: CallManagerDelegate;
  }) {
    this.localPeerID = args.localPeerID;
    this.localDisplayName = args.localDisplayName;
    this.delegate = args.delegate;
  }

  // MARK: Outgoing call

  startCall(args: { peerIDs: string[]; remoteDisplayName: string; isVideoCall: boolean }): void {
    if (this.call && this.call.state !== 'idle') {
      this.delegate.onError('Already in a call');
      return;
    }
    const callID = uuidv4().toLowerCase();
    this.call = {
      callID,
      state: 'outgoing',
      isInitiator: true,
      isVideoCall: args.isVideoCall,
      remotePeerIDs: args.peerIDs,
      remoteDisplayName: args.remoteDisplayName,
      startedAt: null,
      audioMuted: false,
      videoEnabled: args.isVideoCall,
      remoteAudioMuted: {},
      remoteVideoEnabled: {},
    };
    this.emitState();

    const signal = this.buildSignal('offer', args.peerIDs);
    this.delegate.sendSignal(signal, args.peerIDs);

    this.ringTimer = window.setTimeout(() => {
      this.endCall('timeout');
    }, RING_TIMEOUT_MS);
  }

  // MARK: Incoming call

  handleSignal(signal: CallSignal, fromPeerID: string): void {
    switch (signal.signalType) {
      case 'offer':
        this.onOffer(signal, fromPeerID);
        break;
      case 'answer':
        this.onAnswer(signal, fromPeerID);
        break;
      case 'reject':
        this.onReject(signal);
        break;
      case 'end':
        this.onEnd();
        break;
      case 'busy':
        this.onBusy();
        break;
      case 'media_control':
        this.onMediaControl(signal, fromPeerID);
        break;
      case 'request_keyframe':
        this.videoCapture?.forceKeyframe();
        break;
    }
  }

  private onOffer(signal: CallSignal, fromPeerID: string): void {
    if (this.call && this.call.state !== 'idle') {
      // Already in a call — auto-busy.
      const busy: CallSignal = {
        callID: signal.callID,
        signalType: 'busy',
        callerPeerID: this.localPeerID,
        callerDisplayName: this.localDisplayName,
        calleePeerIDs: [fromPeerID],
        isVideoCall: signal.isVideoCall,
        timestamp: appleTimestampNow(),
        mediaControl: null,
      };
      this.delegate.sendSignal(busy, [fromPeerID]);
      return;
    }
    this.call = {
      callID: signal.callID,
      state: 'incoming',
      isInitiator: false,
      isVideoCall: signal.isVideoCall,
      remotePeerIDs: [fromPeerID, ...signal.calleePeerIDs.filter((id) => id !== this.localPeerID)],
      remoteDisplayName: signal.callerDisplayName,
      startedAt: null,
      audioMuted: false,
      videoEnabled: signal.isVideoCall,
      remoteAudioMuted: {},
      remoteVideoEnabled: {},
    };
    this.ringTimer = window.setTimeout(() => {
      this.endCall('timeout');
    }, RING_TIMEOUT_MS);
    this.emitState();
  }

  acceptIncoming(): void {
    if (!this.call || this.call.state !== 'incoming') return;
    this.call.state = 'active';
    this.call.startedAt = Date.now();
    this.clearRingTimer();
    this.emitState();
    const answer = this.buildSignal('answer', this.call.remotePeerIDs);
    this.delegate.sendSignal(answer, this.call.remotePeerIDs);
    void this.startMedia();
  }

  rejectIncoming(): void {
    if (!this.call || this.call.state !== 'incoming') return;
    const target = [...this.call.remotePeerIDs];
    const sig = this.buildSignal('reject', target);
    this.delegate.sendSignal(sig, target);
    this.teardown('rejected');
  }

  // MARK: Outgoing — peer side

  private onAnswer(signal: CallSignal, fromPeerID: string): void {
    void signal;
    if (!this.call || this.call.state !== 'outgoing') return;
    this.clearRingTimer();
    this.call.state = 'active';
    this.call.startedAt = Date.now();
    this.connectTimer = window.setTimeout(() => {
      // No media within window — assume failed.
      this.endCall('error');
    }, CONNECT_TIMEOUT_MS);
    void this.startMedia();
    void fromPeerID;
    this.emitState();
  }

  private onReject(signal: CallSignal): void {
    void signal;
    this.teardown('rejected');
  }

  private onEnd(): void {
    this.teardown('normal');
  }

  private onBusy(): void {
    this.teardown('busy');
  }

  private onMediaControl(signal: CallSignal, fromPeerID: string): void {
    if (!this.call || this.call.callID !== signal.callID) return;
    const c = signal.mediaControl;
    if (!c) return;
    this.call.remoteAudioMuted[fromPeerID] = c.audioMuted;
    this.call.remoteVideoEnabled[fromPeerID] = c.videoEnabled;
    this.emitState();
  }

  // MARK: Local controls

  setAudioMuted(muted: boolean): void {
    if (!this.call || this.call.state !== 'active') return;
    this.call.audioMuted = muted;
    this.audioCapture?.setMuted(muted);
    this.broadcastMediaControl();
    this.emitState();
  }

  setVideoEnabled(enabled: boolean): void {
    if (!this.call || this.call.state !== 'active' || !this.call.isVideoCall) return;
    this.call.videoEnabled = enabled;
    this.videoCapture?.setEnabled(enabled);
    this.broadcastMediaControl();
    this.emitState();
  }

  attachRemoteCanvas(peerID: string, canvas: HTMLCanvasElement | null): void {
    const playback = this.videoPlaybackByPeer.get(peerID);
    if (!playback) return;
    if (canvas) {
      playback.attachCanvas(canvas);
    } else {
      playback.detachCanvas();
    }
  }

  getLocalVideoStream(): MediaStream | null {
    return this.videoCapture?.stream ?? null;
  }

  endCall(reason: CallEndReason = 'normal'): void {
    if (!this.call || this.call.state === 'idle') return;
    if (this.call.state === 'active' || this.call.state === 'outgoing' || this.call.state === 'incoming') {
      const end = this.buildSignal('end', this.call.remotePeerIDs);
      this.delegate.sendSignal(end, this.call.remotePeerIDs);
    }
    this.teardown(reason);
  }

  private broadcastMediaControl(): void {
    if (!this.call) return;
    const payload: MediaControlPayload = {
      audioMuted: this.call.audioMuted,
      videoEnabled: this.call.videoEnabled,
      requestKeyframe: false,
    };
    const sig: CallSignal = {
      callID: this.call.callID,
      signalType: 'media_control',
      callerPeerID: this.localPeerID,
      callerDisplayName: this.localDisplayName,
      calleePeerIDs: this.call.remotePeerIDs,
      isVideoCall: this.call.isVideoCall,
      timestamp: appleTimestampNow(),
      mediaControl: payload,
    };
    this.delegate.sendSignal(sig, this.call.remotePeerIDs);
  }

  // MARK: Media

  private async startMedia(): Promise<void> {
    if (!this.call) return;
    try {
      this.audioCapture = await startAudioCapture({
        onFrame: (samples) => this.handleLocalAudioFrame(samples),
        onError: (err) => this.delegate.onError(err.message),
      });
      // Pre-create playback contexts on user gesture so AudioContext can resume.
      for (const peerID of this.call.remotePeerIDs) {
        const pb = new AudioPlayback();
        await pb.start();
        this.playbackByPeer.set(peerID, pb);
        this.audioReassemblers.set(peerID, new FragmentReassembler());
        const vp = new VideoPlayback();
        vp.start((err) => this.delegate.onError(err.message));
        this.videoPlaybackByPeer.set(peerID, vp);
        this.videoReassemblers.set(peerID, new FragmentReassembler());
      }
      if (this.call.isVideoCall) {
        try {
          this.videoCapture = await startVideoCapture({
            onFrame: (frame) => this.handleLocalVideoFrame(frame),
            onError: (err) => this.delegate.onError(err.message),
          });
        } catch (err) {
          // Video capture failure isn't fatal to a video call — drop to audio
          // and surface the error.
          this.delegate.onError(
            err instanceof Error ? `Camera failed: ${err.message}` : 'Camera failed',
          );
        }
      }
      if (this.connectTimer !== null) {
        window.clearTimeout(this.connectTimer);
        this.connectTimer = null;
      }
      this.emitState();
    } catch (err) {
      this.delegate.onError(
        err instanceof Error ? `Microphone access failed: ${err.message}` : 'Microphone access failed',
      );
      this.endCall('error');
    }
  }

  private handleLocalVideoFrame(frame: { bytes: Uint8Array; isKeyFrame: boolean; sequence: number }): void {
    if (!this.call || this.call.state !== 'active') return;
    const timestamp = frame.sequence * Math.floor(VIDEO.clockHz / VIDEO.fps);
    const fragments = fragmentFrame({
      callID: this.call.callID,
      senderPeerID: this.localPeerID,
      mediaType: 'video',
      sequence: frame.sequence,
      timestamp,
      isKeyFrame: frame.isKeyFrame,
      payload: frame.bytes,
    });
    // Audio rides unreliable for latency; video must be reliable so a single
    // dropped fragment doesn't corrupt a multi-fragment frame.
    for (const fragment of fragments) {
      this.delegate.sendMediaFrame(fragment, this.call.remotePeerIDs, true);
    }
  }

  private handleLocalAudioFrame(samples: Float32Array): void {
    if (!this.call || this.call.state !== 'active') return;
    const seq = ++this.audioSequence;
    // RTP-style timestamp: sample count at 16 kHz.
    const timestamp = seq * AUDIO.samplesPerFrame;
    const payload = new Uint8Array(samples.buffer, samples.byteOffset, samples.byteLength);
    const fragments = fragmentFrame({
      callID: this.call.callID,
      senderPeerID: this.localPeerID,
      mediaType: 'audio',
      sequence: seq,
      timestamp,
      isKeyFrame: false,
      payload,
    });
    for (const fragment of fragments) {
      this.delegate.sendMediaFrame(fragment, this.call.remotePeerIDs, false);
    }
  }

  /** Dispatched by the WebSocket bridge after decrypting an incoming `media_frame` payload. */
  handleMediaFrameBytes(bytes: Uint8Array, fromPeerID: string): void {
    if (!this.call || this.call.state !== 'active') return;
    const unpacked = unpackFrame(bytes);
    if (!unpacked) return;
    const reassemblers =
      unpacked.header.mediaType === 'video'
        ? this.videoReassemblers
        : this.audioReassemblers;
    const reassembler = reassemblers.get(fromPeerID);
    if (!reassembler) return;
    const completed = reassembler.ingest(unpacked);
    if (!completed) return;
    if (completed.header.callID !== this.call.callID) return;
    if (completed.header.mediaType === 'audio') {
      this.handleAudioPlayback(completed.header, completed.payload, fromPeerID);
    } else if (completed.header.mediaType === 'video') {
      this.handleVideoPlayback(completed.header, completed.payload, fromPeerID);
    }
  }

  private handleVideoPlayback(
    header: MediaFrameHeader,
    payload: Uint8Array,
    fromPeerID: string,
  ): void {
    const playback = this.videoPlaybackByPeer.get(fromPeerID);
    if (!playback) return;
    playback.feed({ bytes: payload, isKeyFrame: header.isKeyFrame });
  }

  private handleAudioPlayback(header: MediaFrameHeader, payload: Uint8Array, fromPeerID: string): void {
    const playback = this.playbackByPeer.get(fromPeerID);
    if (!playback) return;
    if (payload.byteLength !== AUDIO.samplesPerFrame * 4) {
      // Unexpected size; drop.
      return;
    }
    // Float32 little-endian on iOS (ARM) and on web — bytes copy across.
    const aligned = new Uint8Array(payload.byteLength);
    aligned.set(payload);
    const samples = new Float32Array(aligned.buffer);
    playback.push(header.sequence, samples);
  }

  // MARK: Helpers

  getCall(): ActiveCall | null {
    return this.call;
  }

  setLocalIdentity(localPeerID: string, displayName: string): void {
    this.localPeerID = localPeerID;
    this.localDisplayName = displayName;
  }

  private buildSignal(type: CallSignalType, peerIDs: string[]): CallSignal {
    return {
      callID: this.call?.callID ?? uuidv4().toLowerCase(),
      signalType: type,
      callerPeerID: this.localPeerID,
      callerDisplayName: this.localDisplayName,
      calleePeerIDs: peerIDs,
      isVideoCall: this.call?.isVideoCall ?? false,
      timestamp: appleTimestampNow(),
      mediaControl: null,
    };
  }

  private teardown(reason: CallEndReason): void {
    void reason;
    this.clearRingTimer();
    if (this.connectTimer !== null) {
      window.clearTimeout(this.connectTimer);
      this.connectTimer = null;
    }
    void this.audioCapture?.stop();
    this.audioCapture = null;
    void this.videoCapture?.stop();
    this.videoCapture = null;
    for (const pb of this.playbackByPeer.values()) {
      void pb.stop();
    }
    this.playbackByPeer.clear();
    this.audioReassemblers.clear();
    for (const vp of this.videoPlaybackByPeer.values()) {
      void vp.stop();
    }
    this.videoPlaybackByPeer.clear();
    this.videoReassemblers.clear();
    this.audioSequence = 0;
    this.call = null;
    this.emitState();
  }

  private clearRingTimer(): void {
    if (this.ringTimer !== null) {
      window.clearTimeout(this.ringTimer);
      this.ringTimer = null;
    }
  }

  private emitState(): void {
    this.delegate.onStateChange(this.call ? { ...this.call } : null);
  }
}
