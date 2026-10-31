// API Client for SyScan Web Dashboard

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000';

export interface UserDto {
  id: string;
  email: string;
  displayName: string;
}

export interface AuthResponse {
  token: string;
  user: UserDto;
  expiresIn?: number;
}

export interface ScanSummary {
  scanId: string;
  participantLabel: string;
  gameId: string;
  status: string;
  createdAt: string;
  connectedAt?: string;
  completedAt?: string;
}

export interface ScanEvent {
  eventType: string;
  message: string;
  moduleId?: string;
  occurredAt: string;
}

export interface ScanFinding {
  findingId: string;
  moduleId: string;
  category: string;
  severity: string;
  title: string;
  description: string;
  filePath?: string;
  fileHash?: string;
  confidence: number;
  occurredAt: string;
  explanation?: string;
}

export interface ScanDetail {
  scanId: string;
  participantLabel: string;
  gameId: string;
  scanProfileId: string;
  status: string;
  createdAt: string;
  connectedAt?: string;
  scanStartedAt?: string;
  completedAt?: string;
  events: ScanEvent[];
  findings: ScanFinding[];
}

export interface ScanReport {
  scanId: string;
  organization: string;
  investigator: string;
  participant: string;
  game: string;
  profile: string;
  status: string;
  timestamps: {
    created: string;
    connected?: string;
    started?: string;
    completed?: string;
    durationSeconds: number;
  };
  summary: {
    totalFindings: number;
    critical: number;
    warning: number;
    suspicious: number;
    clean: boolean;
  };
  findings: ScanFinding[];
  events: {
    type: string;
    message: string;
    moduleId?: string;
    occurredAt: string;
  }[];
}

export interface CreateScanPayload {
  participantLabel: string;
  gameId: string;
  scanProfileId: string;
  enabledModules: string[];
  invitationExpiryMinutes?: number;
}

export interface CreateScanResponse {
  scanId: string;
  sessionId: string;
  invitationToken: string;
  invitationPath: string;
  expiresAt: string;
  status: string;
}

export interface InvitationValidation {
  scanId: string;
  organizationName: string;
  gameId: string;
  participantLabel: string;
  enabledModules: string[];
}

function getAuthHeader(): Record<string, string> {
  if (typeof window === 'undefined') return {};
  const token = localStorage.getItem('syscan_token');
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export async function login(email: string, password: string): Promise<AuthResponse> {
  const res = await fetch(`${API_BASE_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.error || 'Authentication failed. Please check your credentials.');
  }

  const data: AuthResponse = await res.json();
  if (typeof window !== 'undefined') {
    localStorage.setItem('syscan_token', data.token);
    localStorage.setItem('syscan_user', JSON.stringify(data.user));
  }
  return data;
}

export async function register(email: string, password: string, displayName: string): Promise<AuthResponse> {
  const res = await fetch(`${API_BASE_URL}/api/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password, displayName }),
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.error || 'Registration failed.');
  }

  const data: AuthResponse = await res.json();
  if (typeof window !== 'undefined') {
    localStorage.setItem('syscan_token', data.token);
    localStorage.setItem('syscan_user', JSON.stringify(data.user));
  }
  return data;
}

export function logout(): void {
  if (typeof window !== 'undefined') {
    localStorage.removeItem('syscan_token');
    localStorage.removeItem('syscan_user');
  }
}

export async function listScans(page = 1, pageSize = 30): Promise<ScanSummary[]> {
  const res = await fetch(`${API_BASE_URL}/api/scans?page=${page}&pageSize=${pageSize}`, {
    headers: { ...getAuthHeader() },
  });

  if (!res.ok) throw new Error('Failed to load scans list.');
  return res.json();
}

export async function getScan(scanId: string): Promise<ScanDetail> {
  const res = await fetch(`${API_BASE_URL}/api/scans/${scanId}`, {
    headers: { ...getAuthHeader() },
  });

  if (!res.ok) throw new Error(`Failed to load scan '${scanId}'.`);
  return res.json();
}

export async function getScanReport(scanId: string): Promise<ScanReport> {
  const res = await fetch(`${API_BASE_URL}/api/scans/${scanId}/report`, {
    headers: { ...getAuthHeader() },
  });

  if (!res.ok) throw new Error(`Failed to load forensic report for '${scanId}'.`);
  return res.json();
}

export async function createScan(payload: CreateScanPayload): Promise<CreateScanResponse> {
  const res = await fetch(`${API_BASE_URL}/api/scans`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...getAuthHeader(),
    },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.error || 'Failed to create scan request.');
  }

  return res.json();
}

export async function cancelScan(scanId: string): Promise<void> {
  const res = await fetch(`${API_BASE_URL}/api/scans/${scanId}`, {
    method: 'DELETE',
    headers: { ...getAuthHeader() },
  });

  if (!res.ok) throw new Error(`Failed to cancel scan '${scanId}'.`);
}

export async function validateInvitation(token: string): Promise<InvitationValidation> {
  const res = await fetch(`${API_BASE_URL}/api/invite/${token}`);
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.error || 'Invitation is invalid or has expired.');
  }
  return res.json();
}

export async function checkApiHealth(): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE_URL}/api/health`);
    return res.ok;
  } catch {
    return false;
  }
}

