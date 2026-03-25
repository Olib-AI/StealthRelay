/* ---- Outgoing (Guest sends) ---- */

export interface JoinRequestData {
  token_id: string;
  proof: string;
  timestamp: number;
  nonce: string;
  client_public_key: string;
  display_name: string;
  pow_solution?: { challenge: string; solution: string } | null;
}

export interface ForwardData {
  data: string;
  target_peer_ids?: string[] | null;
  sequence: number;
  session_token?: string;
}

export interface AckData {
  sequence: number;
}

export interface HeartbeatPingData {
  timestamp: number;
}

/* ---- Incoming (Guest receives) ---- */

export interface AuthChallengeData {
  nonce: string;
}

export interface PeerInfo {
  peer_id: string;
  display_name: string;
  public_key: string;
  connected_at: number;
}

export interface PoolInfoData {
  pool_id: string;
  name: string;
  host_peer_id: string;
  max_peers: number;
  current_peers: number;
}

export interface JoinAcceptedData {
  session_token: string;
  peer_id: string;
  peers: PeerInfo[];
  pool_info: PoolInfoData;
}

export interface JoinRejectedData {
  reason: string;
}

export interface PeerJoinedData {
  peer: PeerInfo;
}

export interface PeerLeftData {
  peer_id: string;
  reason: string;
}

export interface RelayedData {
  data: string;
  from_peer_id: string;
  sequence: number;
}

export interface ServerErrorData {
  code: number;
  message: string;
}

export interface KickedData {
  reason: string;
}

export interface HeartbeatPongData {
  timestamp: number;
  server_time: number;
}

export interface PowChallenge {
  challenge: string;
  difficulty: number;
  timestamp: number;
}

export interface ServerHelloData {
  server_ephemeral_pk: string;
  server_identity_pk: string;
  pow_challenge?: PowChallenge | null;
  timestamp: number;
  signature: string;
}

export interface SessionResumedData {
  missed_messages: ServerFrame[];
  last_acked_sequence: number;
}

/* ---- Frame wrapper ---- */

export type ServerFrameType =
  | 'auth_challenge'
  | 'join_accepted'
  | 'join_rejected'
  | 'peer_joined'
  | 'peer_left'
  | 'relayed'
  | 'error'
  | 'kicked'
  | 'heartbeat_pong'
  | 'server_hello'
  | 'session_resumed';

export interface ServerFrame {
  frame_type: string;
  data: unknown;
}

export interface ClientFrame {
  frame_type: string;
  data: unknown;
}

export function makeFrame(frameType: string, data: unknown): string {
  return JSON.stringify({ frame_type: frameType, data });
}
