export type ModuleStatus = 'pending' | 'running' | 'success' | 'failed' | 'skipped'
export type InvStatus = 'idle' | 'loading' | 'pending' | 'running' | 'complete' | 'failed'
export type RiskLevel = 'low' | 'medium' | 'high' | 'critical' | 'unknown'

export interface ModuleState {
  name: string
  status: ModuleStatus
  findings: Record<string, unknown>[]
  error?: string
}

export interface InvestigationSummary {
  id: string
  email: string
  status: string
  exposure_score: number | null
  created_at: string
  completed_at: string | null
}

export interface PaginatedInvestigations {
  total: number
  page: number
  page_size: number
  pages: number
  items: InvestigationSummary[]
}

// WebSocket event frames from /ws/investigate/:id
export type WsEvent =
  | { type: 'module_start'; module: string; timestamp: string }
  | { type: 'module_result'; module: string; findings: Record<string, unknown>[]; status: string }
  | { type: 'module_error'; module: string; error: string; status: string }
  | { type: 'investigation_complete'; exposure_score: number | null; risk_level: string }
  | { type: 'error'; error: string }
