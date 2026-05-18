import type { RiskLevel } from '../types'

interface Props {
  level: RiskLevel | string
  size?: 'sm' | 'lg'
}

const CONFIG: Record<string, { label: string; classes: string }> = {
  low:      { label: 'LOW',      classes: 'text-emerald-400 bg-emerald-400/10 border-emerald-400/30' },
  medium:   { label: 'MEDIUM',   classes: 'text-yellow-400  bg-yellow-400/10  border-yellow-400/30'  },
  high:     { label: 'HIGH',     classes: 'text-orange-400  bg-orange-400/10  border-orange-400/30'  },
  critical: { label: 'CRITICAL', classes: 'text-red-400     bg-red-400/10     border-red-400/30'     },
  unknown:  { label: 'UNKNOWN',  classes: 'text-zinc-500    bg-zinc-800       border-zinc-700'        },
}

export default function RiskBadge({ level, size = 'sm' }: Props) {
  const cfg = CONFIG[level] ?? CONFIG.unknown
  return (
    <span
      className={`
        inline-block border font-mono font-bold uppercase tracking-widest
        ${size === 'lg' ? 'px-3 py-1 text-sm rounded-sm' : 'px-2 py-0.5 text-xs rounded-sm'}
        ${cfg.classes}
      `}
    >
      {cfg.label}
    </span>
  )
}
