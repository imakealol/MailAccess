import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api/client'
import { useInvestigationStore } from '../store/investigationStore'
import type { InvestigationSummary, RiskLevel } from '../types'
import RiskBadge from './RiskBadge'
import DeleteConfirmModal from './DeleteConfirmModal'

const MODULE_NAMES = [
  'hibp', 'hunter_io', 'emailrep', 'gravatar', 'google_search',
  'shodan', 'dns_lookup', 'whois_lookup', 'social_links',
]

function scoreToRisk(score: number | null): RiskLevel {
  if (score === null) return 'unknown'
  if (score <= 20) return 'low'
  if (score <= 50) return 'medium'
  if (score <= 80) return 'high'
  return 'critical'
}

function scorePillClass(score: number | null): string {
  if (score === null) return 'text-zinc-500 bg-zinc-800 border-zinc-700'
  if (score <= 20) return 'text-emerald-400 bg-emerald-400/10 border-emerald-400/30'
  if (score <= 50) return 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30'
  if (score <= 80) return 'text-orange-400 bg-orange-400/10 border-orange-400/30'
  return 'text-red-400 bg-red-400/10 border-red-400/30'
}

function dotClass(status: string): string {
  switch (status) {
    case 'complete': return 'bg-emerald-400'
    case 'running':  return 'bg-cyan-400 animate-pulse-dot'
    case 'failed':   return 'bg-red-400'
    default:         return 'bg-zinc-700'
  }
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

interface Props {
  investigation: InvestigationSummary
  onDelete: (id: string) => void
}

export default function InvestigationRow({ investigation, onDelete }: Props) {
  const { id, email, status, exposure_score, created_at } = investigation
  const [rerunning, setRerunning] = useState(false)
  const [showModal, setShowModal] = useState(false)
  const navigate = useNavigate()
  const store = useInvestigationStore()

  async function handleRerun() {
    if (rerunning) return
    setRerunning(true)
    try {
      const res = await api.investigate(email)
      store.initLive(res.id, email)
      navigate(`/investigation/${res.id}`)
    } catch {
      setRerunning(false)
    }
  }

  function handleConfirmDelete() {
    setShowModal(false)
    onDelete(id)
  }

  const dot = dotClass(status)

  return (
    <>
      <div className="flex items-center gap-3 px-4 py-3 bg-zinc-900/40 border border-zinc-800/50 hover:bg-zinc-900 hover:border-zinc-700 transition-colors group font-mono">
        {/* Email */}
        <span
          className="text-sm text-zinc-300 truncate w-52 flex-shrink-0"
          title={email}
        >
          {email}
        </span>

        {/* Timestamp */}
        <span
          className="text-zinc-600 text-xs w-20 flex-shrink-0"
          title={new Date(created_at).toLocaleString()}
        >
          {timeAgo(created_at)}
        </span>

        <div className="flex-1" />

        {/* Exposure score pill */}
        <span className={`text-xs font-bold px-2 py-0.5 border rounded-sm flex-shrink-0 ${scorePillClass(exposure_score)}`}>
          {exposure_score !== null ? exposure_score : '—'}
        </span>

        {/* Risk badge */}
        <div className="flex-shrink-0">
          <RiskBadge level={scoreToRisk(exposure_score)} />
        </div>

        {/* Stat chips */}
        <div className="flex items-center gap-1 flex-shrink-0">
          <span className="text-xs text-zinc-700 bg-zinc-800/50 border border-zinc-800 px-1.5 py-0.5 rounded-sm" title="Findings">
            — fnd
          </span>
          <span className="text-xs text-zinc-700 bg-zinc-800/50 border border-zinc-800 px-1.5 py-0.5 rounded-sm" title="Breaches">
            — brch
          </span>
        </div>

        {/* Module status dots */}
        <div className="flex items-center gap-0.5 flex-shrink-0" title={`Status: ${status}`}>
          {MODULE_NAMES.map(mod => (
            <div key={mod} className={`w-1.5 h-1.5 rounded-full ${dot}`} title={mod} />
          ))}
        </div>

        {/* Action buttons */}
        <div className="flex items-center gap-1 flex-shrink-0">
          <button
            onClick={() => navigate(`/investigation/${id}`)}
            className="text-xs text-zinc-500 hover:text-cyan-400 border border-zinc-800 hover:border-cyan-400/40 px-2 py-1 rounded-sm transition-colors"
          >
            View
          </button>
          <button
            onClick={handleRerun}
            disabled={rerunning}
            className="text-xs text-zinc-500 hover:text-yellow-400 border border-zinc-800 hover:border-yellow-400/40 px-2 py-1 rounded-sm transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
          >
            {rerunning ? '…' : 'Re-run'}
          </button>
          <button
            onClick={() => setShowModal(true)}
            className="text-xs text-zinc-600 hover:text-red-400 border border-zinc-800 hover:border-red-400/40 px-2 py-1 rounded-sm transition-colors"
          >
            Delete
          </button>
        </div>
      </div>

      {showModal && (
        <DeleteConfirmModal
          email={email}
          onConfirm={handleConfirmDelete}
          onCancel={() => setShowModal(false)}
        />
      )}
    </>
  )
}
