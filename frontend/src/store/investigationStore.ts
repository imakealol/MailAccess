import { create } from 'zustand'
import type { ModuleState, ModuleStatus, InvStatus, RiskLevel } from '../types'

const DEFAULT_MODULE_NAMES = [
  'hibp',
  'hunter_io',
  'emailrep',
  'gravatar',
  'google_search',
  'shodan',
  'dns_lookup',
  'whois_lookup',
  'social_links',
]

function blankModules(): Record<string, ModuleState> {
  return Object.fromEntries(
    DEFAULT_MODULE_NAMES.map(name => [
      name,
      { name, status: 'pending' as ModuleStatus, findings: [] },
    ])
  )
}

interface Store {
  id: string | null
  email: string
  status: InvStatus
  exposureScore: number | null
  riskLevel: RiskLevel
  modules: Record<string, ModuleState>
  totalFindings: number
  breachCount: number

  initLive: (id: string, email: string) => void
  loadReport: (report: Record<string, unknown>) => void
  handleWsModuleStart: (module: string) => void
  handleWsModuleResult: (module: string, findings: Record<string, unknown>[], status: string) => void
  handleWsModuleError: (module: string, error: string) => void
  handleWsComplete: (score: number | null, riskLevel: string) => void
  setStatus: (status: InvStatus) => void
  reset: () => void
}

export const useInvestigationStore = create<Store>((set) => ({
  id: null,
  email: '',
  status: 'idle',
  exposureScore: null,
  riskLevel: 'unknown',
  modules: blankModules(),
  totalFindings: 0,
  breachCount: 0,

  initLive(id, email) {
    set({
      id,
      email,
      status: 'running',
      exposureScore: null,
      riskLevel: 'unknown',
      modules: blankModules(),
      totalFindings: 0,
      breachCount: 0,
    })
  },

  loadReport(report) {
    const modules = blankModules()
    const runs = (report.module_runs as Record<string, unknown>[] | undefined) ?? []
    const findings = (report.findings as Record<string, unknown>[] | undefined) ?? []

    for (const run of runs) {
      const name = run.module_name as string
      const rawStatus = run.status as string
      const status: ModuleStatus =
        rawStatus === 'success' ? 'success'
        : rawStatus === 'failed' ? 'failed'
        : rawStatus === 'partial' ? 'success'
        : 'skipped'
      modules[name] = {
        name,
        status,
        findings: findings
          .filter(f => f.module_name === name)
          .map(f => f.data as Record<string, unknown>),
        error: run.error as string | undefined,
      }
    }

    const rawStatus = report.status as string
    const invStatus: InvStatus =
      rawStatus === 'complete' ? 'complete'
      : rawStatus === 'running' ? 'running'
      : rawStatus === 'failed' ? 'failed'
      : 'pending'

    set({
      id: report.id as string,
      email: report.email as string,
      status: invStatus,
      exposureScore: (report.exposure_score as number | null) ?? null,
      riskLevel: ((report.risk_level as string) || 'unknown') as RiskLevel,
      modules,
      totalFindings: findings.length,
      breachCount: findings.filter(f => f.module_name === 'hibp').length,
    })
  },

  handleWsModuleStart(module) {
    set(s => ({
      modules: {
        ...s.modules,
        [module]: {
          ...(s.modules[module] ?? { name: module, findings: [] }),
          status: 'running' as ModuleStatus,
        },
      },
    }))
  },

  handleWsModuleResult(module, findings, statusStr) {
    set(s => {
      const prev = s.modules[module] ?? { name: module, findings: [] }
      const newFindings = [...prev.findings, ...findings]
      const status: ModuleStatus = statusStr === 'success' ? 'success' : 'failed'
      return {
        modules: { ...s.modules, [module]: { ...prev, status, findings: newFindings } },
        totalFindings: s.totalFindings + findings.length,
        breachCount:
          module === 'hibp'
            ? s.breachCount + findings.length
            : s.breachCount,
      }
    })
  },

  handleWsModuleError(module, error) {
    set(s => ({
      modules: {
        ...s.modules,
        [module]: {
          ...(s.modules[module] ?? { name: module, findings: [] }),
          status: 'failed' as ModuleStatus,
          error,
        },
      },
    }))
  },

  handleWsComplete(score, riskLevel) {
    set({ status: 'complete', exposureScore: score, riskLevel: riskLevel as RiskLevel })
  },

  setStatus(status) {
    set({ status })
  },

  reset() {
    set({
      id: null,
      email: '',
      status: 'idle',
      exposureScore: null,
      riskLevel: 'unknown',
      modules: blankModules(),
      totalFindings: 0,
      breachCount: 0,
    })
  },
}))
