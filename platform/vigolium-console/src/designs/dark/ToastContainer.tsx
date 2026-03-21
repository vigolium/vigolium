interface Toast {
  id: string;
  message: string;
  type: 'success' | 'error' | 'info';
}

const BORDER_COLORS: Record<string, string> = {
  success: '#98bc37',
  error: '#ef2f27',
  info: '#68a8e4',
};

export default function ToastContainer({ toasts, onDismiss }: { toasts: Toast[]; onDismiss: (id: string) => void }) {
  if (toasts.length === 0) return null;

  return (
    <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2">
      {toasts.map((t) => (
        <div
          key={t.id}
          className="animate-toast-in bg-[#272520] border border-[#2e2b26] text-[#fce8c3] text-xs px-3 py-2 flex items-center gap-2 max-w-xs shadow-lg"
          style={{ borderLeftWidth: 3, borderLeftColor: BORDER_COLORS[t.type] }}
        >
          <span className="flex-1">{t.message}</span>
          <button onClick={() => onDismiss(t.id)} className="text-[#918175] hover:text-[#fce8c3] shrink-0">[x]</button>
        </div>
      ))}
    </div>
  );
}
