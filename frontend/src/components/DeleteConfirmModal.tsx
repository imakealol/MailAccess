interface Props {
  email: string
  onConfirm: () => void
  onCancel: () => void
}

export default function DeleteConfirmModal({ email, onConfirm, onCancel }: Props) {
  return (
    <div
      className="fixed inset-0 bg-zinc-950/80 backdrop-blur-sm flex items-center justify-center z-50"
      onClick={e => { if (e.target === e.currentTarget) onCancel() }}
    >
      <div className="bg-zinc-900 border border-zinc-800 rounded-sm shadow-2xl w-full max-w-sm mx-4 p-6 font-mono">
        <h2 className="text-xs font-bold text-zinc-100 uppercase tracking-widest mb-4">
          Delete Investigation
        </h2>

        <p className="text-zinc-500 text-xs mb-2">
          Permanently delete the investigation for:
        </p>
        <p className="text-sm text-zinc-300 bg-zinc-800/60 border border-zinc-800 px-3 py-2 rounded-sm mb-5 truncate">
          {email}
        </p>

        <div className="flex gap-2 justify-end">
          <button
            onClick={onCancel}
            className="text-xs text-zinc-400 hover:text-zinc-200 border border-zinc-700 hover:border-zinc-600 px-4 py-2 rounded-sm transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            className="text-xs text-red-400 hover:text-red-300 bg-red-400/10 hover:bg-red-400/20 border border-red-400/30 hover:border-red-400/60 px-4 py-2 rounded-sm transition-colors"
          >
            Delete
          </button>
        </div>
      </div>
    </div>
  )
}
