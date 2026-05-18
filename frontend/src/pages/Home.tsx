import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api/client'
import { useInvestigationStore } from '../store/investigationStore'
import type { InvestigationSummary } from '../types'

function scoreToRiskLabel(score: number | null): { label: string; cls: string } {
  if (score === null) return { label: 'N/A', cls: 'text-zinc-600' }
  if (score <= 20) return { label: 'LOW', cls: 'text-emerald-400' }
  if (score <= 50) return { label: 'MED', cls: 'text-yellow-400' }
  if (score <= 80) return { label: 'HIGH', cls: 'text-orange-400' }
  return { label: 'CRIT', cls: 'text-red-400' }
}

function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime()
  const m = Math.floor(diff / 60000)
  if (m < 1) return 'just now'
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

export default function Home() {
  const [email, setEmail] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [recent, setRecent] = useState<InvestigationSummary[]>([])
  const inputRef = useRef<HTMLInputElement>(null)
  const navigate = useNavigate()
  const store = useInvestigationStore()

  useEffect(() => {
    api.listInvestigations().then(r => setRecent(r.items)).catch(() => {})
    inputRef.current?.focus()
  }, [])

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    const trimmed = email.trim()
    if (!trimmed || loading) return
    setError(null)
    setLoading(true)
    try {
      const res = await api.investigate(trimmed)
      store.initLive(res.id, trimmed)
      navigate(`/investigation/${res.id}`)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start investigation')
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-zinc-950 flex flex-col overflow-hidden">
      {/* Animated grid background */}
      <div className="absolute inset-0 bg-grid-fade pointer-events-none" />

      {/* Center hero */}
      <div className="flex-1 flex flex-col items-center justify-center relative z-10 px-4">
        {/* Logo */}
        <div className="mb-10 text-center select-none">
          <div className="flex items-center justify-center gap-3 mb-3">
            <svg width="28" height="28" viewBox="0 0 28 28" fill="none">
              <polygon
                points="14,2 26,8 26,20 14,26 2,20 2,8"
                stroke="#22d3ee"
                strokeWidth="1.5"
                fill="rgba(34,211,238,0.06)"
              />
              <polygon
                points="14,7 21,11 21,17 14,21 7,17 7,11"
                stroke="#22d3ee"
                strokeWidth="1"
                fill="rgba(34,211,238,0.1)"
              />
            </svg>
            <h1 className="text-3xl font-bold tracking-[0.2em] text-zinc-100 uppercase text-glow-cyan">
              MailAccess
            </h1>
          </div>
          <p className="text-zinc-600 text-xs tracking-[0.15em] uppercase">
            OSINT Email Intelligence Platform
          </p>
        </div>

        {/* Search form */}
        <form onSubmit={handleSubmit} className="w-full max-w-lg">
          <div className="flex gap-0">
            <div className="flex-1 relative">
              <input
                ref={inputRef}
                type="email"
                placeholder="target@example.com"
                value={email}
                onChange={e => setEmail(e.target.value)}
                disabled={loading}
                className="
                  w-full bg-zinc-900 border border-zinc-700 border-r-0
                  text-zinc-100 placeholder-zinc-700
                  px-4 py-3 text-sm font-mono
                  rounded-l-sm
                  focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/20
                  disabled:opacity-50
                  transition-colors
                "
              />
              {loading && (
                <span className="absolute right-3 top-1/2 -translate-y-1/2 text-cyan-400 text-xs animate-pulse">
                  ●
                </span>
              )}
            </div>
            <button
              type="submit"
              disabled={loading || !email.trim()}
              className="
                px-6 py-3 bg-cyan-400 text-zinc-950
                text-xs font-bold uppercase tracking-[0.15em]
                rounded-r-sm
                hover:bg-cyan-300
                disabled:opacity-40 disabled:cursor-not-allowed
                transition-colors whitespace-nowrap
              "
            >
              {loading ? 'Starting…' : 'Investigate'}
            </button>
          </div>

          {error && (
            <p className="mt-2 text-red-400 text-xs font-mono pl-1">
              ✗ {error}
            </p>
          )}
        </form>

        {/* Tagline stats */}
        <div className="mt-6 flex gap-6 text-zinc-700 text-xs">
          <span>9 modules</span>
          <span className="text-zinc-800">·</span>
          <span>real-time streaming</span>
          <span className="text-zinc-800">·</span>
          <span>6 export formats</span>
        </div>
      </div>

      {/* Recent investigations */}
      {recent.length > 0 && (
        <div className="relative z-10 max-w-2xl mx-auto w-full px-4 pb-10">
          <div className="flex items-center gap-3 mb-3">
            <span className="text-zinc-700 text-xs uppercase tracking-widest font-mono">
              Recent
            </span>
            <div className="flex-1 h-px bg-zinc-800" />
          </div>

          <div className="space-y-px">
            {recent.map(inv => {
              const risk = scoreToRiskLabel(inv.exposure_score)
              return (
                <button
                  key={inv.id}
                  onClick={() => navigate(`/investigation/${inv.id}`)}
                  className="
                    w-full flex items-center gap-4 px-4 py-2.5
                    bg-zinc-900/40 border border-zinc-800/50
                    hover:bg-zinc-900 hover:border-zinc-700
                    transition-colors text-left
                    group
                  "
                >
                  <span className="font-mono text-sm text-zinc-400 group-hover:text-zinc-200 flex-1 truncate transition-colors">
                    {inv.email}
                  </span>
                  <span className="text-zinc-700 text-xs font-mono">{timeAgo(inv.created_at)}</span>
                  {inv.exposure_score !== null && (
                    <span className="text-xs font-mono text-zinc-600">
                      <span className="text-zinc-500">score </span>
                      <span className="text-cyan-400">{inv.exposure_score}</span>
                    </span>
                  )}
                  <span className={`text-xs font-mono font-bold ${risk.cls}`}>{risk.label}</span>
                  <span className="text-zinc-700 group-hover:text-zinc-500 transition-colors text-xs">→</span>
                </button>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}
