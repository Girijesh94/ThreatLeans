export type Role = 'analyst' | 'reviewer' | 'admin'
export type Profile = { username: string; role: Role; csrf: string; local?: boolean }
export type Provider = { id: string; configured: boolean; model: string; external: boolean }
export type Evidence = { id: string; title: string; source: string; url: string; kind: string; excerpt: string; facts: Record<string, unknown>; sha256: string; fetched_at: string; rank_score: number; match: string }
export type Claim = { text: string; field: string; value: unknown; evidence: string[]; status: string; source_hash: string; corroborated_by: string[] }
export type Result = { answer: string; status: string; claims: Claim[]; evidence: Evidence[]; retrieval_mode: string; trace: { role: string; detail: string }[]; warnings: string[]; limitations: string[]; elapsed_ms: number; corpus_generation: string; verification_mode: string; live_checks: {source: string; cve: string; status: string}[]; ai: null | {text: string; provider: string; model: string; verification: string; attempts: {provider: string; status: string; elapsed_ms: number; reason?: string}[]} }
export type Investigation = { id: string; owner: string; question: string; status: string; created_at: string; review_status: string; review_note: string; reviewer: string; result: Result }
export type LibraryRecord = Omit<Evidence, 'excerpt' | 'rank_score' | 'match'> & {text: string}
export type Overview = { counts: Record<string, number>; sources: Record<string, number>; pending_reviews: number; recent: Investigation[]; retrieval_mode: string; providers: Provider[] }
export type Sources = {feeds: {id: string; url: string}[]; totals: Record<string, number>; runs: {id: string; source: string; status: string; count: number; error: string; created_at: string}[]}
export type Settings = {providers: Provider[]; auth_required: boolean; retrieval_mode: string; dense_enabled: boolean; dense_error: string; embedding_model: string; history_retention_days: number; deployment: string}
export type TeamUser = {id: string; username: string; role: Role; active: boolean}
export type AuditEvent = {actor: string; action: string; detail: Record<string, unknown>; created_at: string}

let csrf = ''
export function setCsrf(value: string) { csrf = value }

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message) }
}

export async function request<T>(path: string, body?: unknown): Promise<T> {
  const response = await fetch('/api' + path, {
    method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    ...(body === undefined ? {} : {body: JSON.stringify(body)}),
  })
  if (!response.ok) {
    const error = await response.json().catch(() => ({detail: response.statusText}))
    throw new ApiError(response.status, typeof error.detail === 'string' ? error.detail : 'Check the submitted fields.')
  }
  return response.json() as Promise<T>
}

export function date(value: string) {
  const parsed = new Date(value.endsWith('Z') || /[+-]\d\d:\d\d$/.test(value) ? value : value + 'Z')
  return Number.isNaN(parsed.getTime()) ? 'Unknown observation date' : parsed.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

export function safeLink(value: string) {
  try { const url = new URL(value); return url.protocol === 'https:' || url.protocol === 'http:' ? value : undefined }
  catch { return undefined }
}
