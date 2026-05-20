import type { PaginatedInvestigations } from '../types'

const BASE = '/api'

export interface GraphNode {
  id: string
  type: string
  label: string
  value: string
  degree?: number
  high_confidence_node?: boolean
  metadata?: Record<string, unknown>
}

export interface GraphLink {
  source: string
  target: string
  type: string
  metadata?: Record<string, unknown>
}

export interface InvestigateResponse {
  id: string
  status: string
  created_at: string
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText)
    throw new Error(`${res.status}: ${text}`)
  }
  if (res.status === 204) return undefined as T
  return res.json() as Promise<T>
}

export const api = {
  investigate(email: string): Promise<InvestigateResponse> {
    return request('/investigate', {
      method: 'POST',
      body: JSON.stringify({ email }),
    })
  },

  getReport(id: string): Promise<Record<string, unknown>> {
    return request(`/report/${id}`)
  },

  getGraph(id: string): Promise<{ nodes: GraphNode[]; links: GraphLink[] }> {
    return request(`/report/${id}/graph`)
  },

  listInvestigations(page = 1, pageSize = 10): Promise<PaginatedInvestigations> {
    return request(`/investigations?page=${page}&page_size=${pageSize}`)
  },

  deleteInvestigation(id: string): Promise<void> {
    return request(`/investigation/${id}`, { method: 'DELETE' })
  },

  exportUrl(id: string, format: string): string {
    return `${BASE}/report/${id}/export?format=${format}`
  },
}
