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
    consent?: string;
    started?: string;
    completed?: string;
    generated?: string;
    durationSeconds: number;
  };
  summary: {
    totalFindings: number;
    critical: number;
    warning: number;
    suspicious: number;
    informational?: number;
    clean: boolean;
    filesDiscovered?: number;
    filesAnalyzed?: number;
    securityFindings?: number;
  };
  fileInventorySummary?: {
    totalDiscovered: number;
    totalExe: number;
    totalJar: number;
    totalDll: number;
    totalSys: number;
    totalOther: number;
    totalSigned: number;
    totalUnsigned: number;
    totalHashed: number;
    inaccessible: number;
  };
  findings: ScanFinding[];
  events: {
    type: string;
    message: string;
    moduleId?: string;
    occurredAt: string;
  }[];
  topInventory?: FileInventoryItem[];
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
    if (res.status === 401) {
      if (typeof window !== 'undefined') {
        localStorage.removeItem('syscan_token');
        localStorage.removeItem('syscan_user');
      }
      throw new Error('Your authentication session has expired. Please log in again.');
    }
    const errorData = await res.json().catch(() => ({}));
    const message = errorData.error 
      || errorData.detail 
      || errorData.title 
      || (errorData.errors ? Object.values(errorData.errors).flat().join(', ') : null)
      || `Failed to create scan request (HTTP ${res.status}).`;
    throw new Error(message);
  }

  return res.json();
}

export interface FileInventoryItem {
  fileId: string;
  fileName: string;
  fullPath: string;
  extension: string;
  actualFileType: string;
  fileSizeBytes: number;
  sha256Hash: string;
  creationTimeUtc: string;
  lastWriteTimeUtc: string;
  lastAccessTimeUtc?: string;
  digitalSignatureState: string;
  publisher?: string;
  productName?: string;
  productVersion?: string;
  discoverySource: string;
  associatedGame?: string;
  fileAnalysisStatus: string;
  detectionStatus: string;
  discoveryContext: string;
  detectionNotes?: string;
}

export interface FileInventoryResponse {
  scanId: string;
  totalItems: number;
  page: number;
  pageSize: number;
  totalPages: number;
  summary: {
    totalFiles: number;
    totalExe: number;
    totalJar: number;
    totalDll: number;
    totalSys: number;
    totalSigned: number;
    totalUnsigned: number;
    totalHashed: number;
  };
  items: FileInventoryItem[];
}

export async function getScanInventory(
  scanId: string,
  params: {
    extension?: string;
    game?: string;
    status?: string;
    search?: string;
    page?: number;
    pageSize?: number;
  } = {}
): Promise<FileInventoryResponse> {
  const query = new URLSearchParams();
  if (params.extension) query.append('extension', params.extension);
  if (params.game) query.append('game', params.game);
  if (params.status) query.append('status', params.status);
  if (params.search) query.append('search', params.search);
  if (params.page) query.append('page', params.page.toString());
  if (params.pageSize) query.append('pageSize', params.pageSize.toString());

  const res = await fetch(`${API_BASE_URL}/api/scans/${scanId}/inventory?${query.toString()}`, {
    headers: { ...getAuthHeader() },
  });

  if (!res.ok) throw new Error(`Failed to load file inventory for scan '${scanId}'.`);
  return res.json();
}

export function getScanInventoryCsvUrl(scanId: string): string {
  return `${API_BASE_URL}/api/scans/${scanId}/inventory?format=csv`;
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

