import { useInvestigationStore } from '../store/investigationStore'
import ExposureGauge from './ExposureGauge'
import RiskBadge from './RiskBadge'

function Metric({ label, value, highlight }: { label: string; value: number; highlight?: boolean }) {
  return (
    <div className="min-w-[64px]">
      <div className="text-zinc-600 text-xs uppercase tracking-widest mb-1 whitespace-nowrap">{label}</div>
      <div className={`text-xl font-bold font-mono ${highlight && value > 0 ? 'text-red-400' : 'text-zinc-100'}`}>
        {value}
      </div>
    </div>
  )
}

function credentialBandClass(band: string): string {
  switch (band) {
    case 'CRITICAL':
      return 'text-red-300 bg-red-500/10 border-red-500/30'
    case 'HIGH':
      return 'text-orange-300 bg-orange-500/10 border-orange-500/30'
    case 'MODERATE':
      return 'text-yellow-300 bg-yellow-500/10 border-yellow-500/30'
    default:
      return 'text-emerald-300 bg-emerald-500/10 border-emerald-500/30'
  }
}

export default function SummaryBar() {
  const {
    exposureScore,
    riskLevel,
    credentialRiskScore,
    credentialRiskBand,
    totalFindings,
    breachCount,
    modules,
  } = useInvestigationStore()

  const accountsFound = Object.values(modules).filter(m => m.findings.length > 0).length

  return (
    <div className="border-b border-zinc-800 bg-zinc-900/50 px-5 py-4 flex items-center gap-6 flex-shrink-0 overflow-x-auto">
      <div className="flex items-center gap-3 flex-shrink-0">
        <ExposureGauge score={exposureScore ?? 0} />
        <div>
          <div className="text-zinc-600 text-xs uppercase tracking-widest mb-0.5">Exposure</div>
          <div className="text-2xl font-bold text-zinc-100 leading-none">
            {exposureScore !== null ? exposureScore : '-'}
          </div>
        </div>
      </div>

      <div className="h-10 w-px bg-zinc-800 flex-shrink-0" />

      <div className="flex-shrink-0">
        <div className="text-zinc-600 text-xs uppercase tracking-widest mb-1.5">Risk</div>
        <RiskBadge level={riskLevel} size="lg" />
      </div>

      <div className="h-10 w-px bg-zinc-800 flex-shrink-0" />

      <div className="flex-shrink-0">
        <div className="text-zinc-600 text-xs uppercase tracking-widest mb-1.5">Cred Risk</div>
        <div className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-sm font-bold ${credentialBandClass(credentialRiskBand)}`}>
          <span>{credentialRiskScore !== null ? credentialRiskScore : '-'}</span>
          <span>{credentialRiskBand}</span>
        </div>
      </div>

      <div className="h-10 w-px bg-zinc-800 flex-shrink-0" />

      <div className="flex gap-5 flex-shrink-0">
        <Metric label="Accounts" value={accountsFound} />
        <Metric label="Breaches" value={breachCount} highlight />
        <Metric label="Data pts" value={totalFindings} />
      </div>
    </div>
  )
}
