import { useState, useEffect, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api/client'
import type { InvestigationSummary } from '../types'
import InvestigationRow from '../components/InvestigationRow'
import NavBar from '../components/NavBar'

type SortKey = 'date' | 'score'
type SortDir = 'asc' | 'desc'

const PAGE_SIZE = 20

function SkeletonRow() {
  return (
    <div className="flex items-center gap-3 px-4 py-3 bg-zinc-900/40 border border-zinc-800/50 animate-pulse">
      <div className="h-3 bg-zinc-800 rounded w-48 flex-shrink-0" />
      <div className="h-3 bg-zinc-800 rounded w-16 flex-shrink-0" />
      <div className="flex-1" />
      <div className="h-5 bg-zinc-800 rounded w-10 flex-shrink-0" />
      <div className="h-5 bg-zinc-800 rounded w-16 flex-shrink-0" />
      <div className="flex gap-1 flex-shrink-0">
        <div className="h-5 bg-zinc-800 rounded w-12" />
        <div className="h-5 bg-zinc-800 rounded w-12" />
      </div>
      <div className="flex gap-0.5 flex-shrink-0">
        {Array.from({ length: 9 }).map((_, i) => (
          <div key={i} className="w-1.5 h-1.5 rounded-full bg-zinc-800" />
        ))}
      </div>
      <div className="flex gap-1 flex-shrink-0">
        <div className="h-6 bg-zinc-800 rounded w-9" />
        <div className="h-6 bg-zinc-800 rounded w-14" />
        <div className="h-6 bg-zinc-800 rounded w-12" />
      </div>
    </div>
  )
}

function SortButton({
  label,
  active,
  dir,
  onClick,
}: {
  label: string
  active: boolean
  dir: SortDir
  onClick: () => void
}) {
  return (
    <button
      onClick={onClick}
      className={`
        text-xs px-2.5 py-1 rounded-sm border transition-colors font-mono
        ${active
          ? 'text-cyan-400 border-cyan-400/30 bg-cyan-400/5'
          : 'text-zinc-600 border-zinc-800 hover:border-zinc-700 hover:text-zinc-400'
        }
      `}
    >
      {label}{active ? (dir === 'desc' ? ' ↓' : ' ↑') : ''}
    </button>
  )
}

export default function HistoryPage() {
  const [items, setItems] = useState<InvestigationSummary[]>([])
  const [total, setTotal] = useState(0)
  const [pages, setPages] = useState(1)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('')
  const [sortKey, setSortKey] = useState<SortKey>('date')
  const [sortDir, setSortDir] = useState<SortDir>('desc')
  const navigate = useNavigate()

  useEffect(() => {
    setLoading(true)
    api
      .listInvestigations(page, PAGE_SIZE)
      .then(r => {
        setItems(r.items)
        setTotal(r.total)
        setPages(r.pages)
      })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [page])

  function handleDelete(id: string) {
    const removed = items.find(inv => inv.id === id)
    setItems(prev => prev.filter(inv => inv.id !== id))
    setTotal(prev => prev - 1)

    api.deleteInvestigation(id).catch(() => {
      if (removed) {
        setItems(prev =>
          [...prev, removed].sort(
            (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
          )
        )
        setTotal(prev => prev + 1)
      }
    })
  }

  function toggleSort(key: SortKey) {
    if (sortKey === key) {
      setSortDir(d => (d === 'asc' ? 'desc' : 'asc'))
    } else {
      setSortKey(key)
      setSortDir('desc')
    }
  }

  const filtered = useMemo(() => {
    const base = filter
      ? items.filter(inv => inv.email.toLowerCase().includes(filter.toLowerCase()))
      : items

    return [...base].sort((a, b) => {
      if (sortKey === 'date') {
        const diff = new Date(a.created_at).getTime() - new Date(b.created_at).getTime()
        return sortDir === 'desc' ? -diff : diff
      }
      const sa = a.exposure_score ?? -1
      const sb = b.exposure_score ?? -1
      return sortDir === 'desc' ? sb - sa : sa - sb
    })
  }, [items, filter, sortKey, sortDir])

  return (
    <div className="min-h-screen bg-zinc-950 flex flex-col font-mono">
      <NavBar />

      <div className="flex-1 max-w-6xl mx-auto w-full px-5 py-6 flex flex-col gap-5">
        {/* Page header */}
        <div className="flex items-center gap-3">
          <span className="text-zinc-300 text-sm font-bold uppercase tracking-widest">
            Investigation History
          </span>
          {!loading && (
            <span className="text-zinc-700 text-xs">
              {total} total
            </span>
          )}
        </div>

        {/* Controls */}
        <div className="flex items-center gap-3 flex-wrap">
          <input
            type="text"
            placeholder="Filter by email…"
            value={filter}
            onChange={e => setFilter(e.target.value)}
            className="
              bg-zinc-900 border border-zinc-800 text-zinc-300 placeholder-zinc-700
              px-3 py-1.5 text-xs font-mono rounded-sm w-64
              focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/10
              transition-colors
            "
          />
          <div className="flex items-center gap-1.5 ml-auto">
            <span className="text-zinc-700 text-xs mr-1">Sort:</span>
            <SortButton
              label="Date"
              active={sortKey === 'date'}
              dir={sortDir}
              onClick={() => toggleSort('date')}
            />
            <SortButton
              label="Score"
              active={sortKey === 'score'}
              dir={sortDir}
              onClick={() => toggleSort('score')}
            />
          </div>
        </div>

        {/* List */}
        <div className="flex flex-col gap-px">
          {loading ? (
            Array.from({ length: 5 }).map((_, i) => <SkeletonRow key={i} />)
          ) : filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-24 text-zinc-700">
              <span className="text-3xl mb-4">○</span>
              {total === 0 ? (
                <>
                  <p className="text-sm mb-5">No investigations yet.</p>
                  <button
                    onClick={() => navigate('/')}
                    className="text-xs text-cyan-400 hover:text-cyan-300 border border-cyan-400/30 hover:border-cyan-400/60 px-4 py-2 rounded-sm transition-colors"
                  >
                    Start your first investigation →
                  </button>
                </>
              ) : (
                <p className="text-sm">No results match your filter.</p>
              )}
            </div>
          ) : (
            filtered.map(inv => (
              <InvestigationRow
                key={inv.id}
                investigation={inv}
                onDelete={handleDelete}
              />
            ))
          )}
        </div>

        {/* Pagination */}
        {!loading && pages > 1 && (
          <div className="flex items-center justify-center gap-4 pt-2">
            <button
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={page === 1}
              className="text-xs text-zinc-500 hover:text-zinc-200 disabled:opacity-30 disabled:cursor-not-allowed border border-zinc-800 hover:border-zinc-700 px-3 py-1.5 rounded-sm transition-colors"
            >
              ← Prev
            </button>
            <span className="text-xs text-zinc-600 tabular-nums">
              {page} / {pages}
            </span>
            <button
              onClick={() => setPage(p => Math.min(pages, p + 1))}
              disabled={page === pages}
              className="text-xs text-zinc-500 hover:text-zinc-200 disabled:opacity-30 disabled:cursor-not-allowed border border-zinc-800 hover:border-zinc-700 px-3 py-1.5 rounded-sm transition-colors"
            >
              Next →
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
