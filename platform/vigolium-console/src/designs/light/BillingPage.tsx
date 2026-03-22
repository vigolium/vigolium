'use client';

import { useState } from 'react';
import { Coins, CreditCard, ExternalLink, Receipt, Sparkles } from 'lucide-react';
import { useCredits, useCreateCheckout, usePaymentHistory, useCreatePortalSession } from '@/api/hooks';
import { useToast } from '@/contexts/ToastContext';
import { SCAN_COSTS, SCAN_LABELS } from '@/lib/billing-costs';
import PageShell from './PageShell';

const PACKAGES = [
  { credits: 100, price: 10, label: 'Starter' },
  { credits: 500, price: 40, label: 'Pro', highlight: true },
  { credits: 1000, price: 70, label: 'Team' },
];

export default function BillingPage() {
  const { data: billing, isLoading: creditsLoading } = useCredits();
  const { data: history } = usePaymentHistory();
  const checkout = useCreateCheckout();
  const portal = useCreatePortalSession();
  const { toast } = useToast();
  const [loadingPkg, setLoadingPkg] = useState<number | null>(null);

  const handleCheckout = async (credits: number) => {
    setLoadingPkg(credits);
    try {
      const res = await checkout.mutateAsync({ credits_amount: credits });
      if (res.url) window.location.href = res.url;
    } catch (err) {
      toast(err instanceof Error ? err.message : 'Checkout failed', 'error');
    } finally {
      setLoadingPkg(null);
    }
  };

  const handlePortal = async () => {
    try {
      const res = await portal.mutateAsync();
      if (res.url) window.location.href = res.url;
    } catch (err) {
      toast(err instanceof Error ? err.message : 'Portal failed', 'error');
    }
  };

  return (
    <PageShell>
      <div className="p-4 max-w-5xl mx-auto space-y-6">
        {/* Credit Balance */}
        <div
          className="p-6 rounded border text-center"
          style={{ borderColor: 'var(--v-border)', backgroundColor: 'color-mix(in srgb, var(--v-surface) 50%, transparent)' }}
        >
          <div className="flex items-center justify-center gap-2 mb-2" style={{ color: 'var(--v-text-muted)' }}>
            <Coins className="w-4 h-4" />
            <span className="text-xs uppercase tracking-wider">Available Credits</span>
          </div>
          <div className="text-5xl font-bold" style={{ color: 'var(--v-accent)' }}>
            {creditsLoading ? '...' : (billing?.credits ?? 0).toLocaleString()}
          </div>
          {billing?.org_name && (
            <div className="text-xs mt-2" style={{ color: 'var(--v-text-muted)' }}>
              {billing.org_name}
            </div>
          )}
        </div>

        {/* Top Up Packages */}
        <div>
          <h2 className="text-sm font-bold mb-3 flex items-center gap-2" style={{ color: 'var(--v-text)' }}>
            <Sparkles className="w-4 h-4" />
            Top Up Credits
          </h2>
          <div className="grid grid-cols-3 gap-3">
            {PACKAGES.map((pkg) => (
              <button
                key={pkg.credits}
                onClick={() => handleCheckout(pkg.credits)}
                disabled={loadingPkg !== null}
                className="p-4 rounded border text-left transition-all hover:scale-[1.02]"
                style={{
                  borderColor: pkg.highlight ? 'var(--v-accent)' : 'var(--v-border)',
                  backgroundColor: pkg.highlight
                    ? 'color-mix(in srgb, var(--v-accent) 8%, transparent)'
                    : 'color-mix(in srgb, var(--v-surface) 30%, transparent)',
                }}
              >
                <div className="text-xs uppercase tracking-wider mb-1" style={{ color: 'var(--v-text-muted)' }}>
                  {pkg.label}
                </div>
                <div className="text-2xl font-bold" style={{ color: 'var(--v-text)' }}>
                  {pkg.credits.toLocaleString()}
                </div>
                <div className="text-xs" style={{ color: 'var(--v-text-muted)' }}>credits</div>
                <div className="text-lg font-bold mt-2" style={{ color: 'var(--v-accent)' }}>
                  ${pkg.price}
                </div>
                <div className="text-xs" style={{ color: 'var(--v-text-muted)' }}>
                  ${(pkg.price / pkg.credits * 100).toFixed(1)}c per credit
                </div>
                {loadingPkg === pkg.credits && (
                  <div className="text-xs mt-2" style={{ color: 'var(--v-accent)' }}>
                    Redirecting...
                  </div>
                )}
              </button>
            ))}
          </div>
        </div>

        {/* Manage Billing */}
        <div className="flex gap-3">
          <button
            onClick={handlePortal}
            className="flex items-center gap-2 px-3 py-1.5 text-xs rounded border transition-colors"
            style={{ borderColor: 'var(--v-border)', color: 'var(--v-text)' }}
          >
            <CreditCard className="w-3 h-3" />
            Manage Billing
            <ExternalLink className="w-3 h-3" />
          </button>
        </div>

        {/* Scan Costs Reference */}
        <div>
          <h2 className="text-sm font-bold mb-3 flex items-center gap-2" style={{ color: 'var(--v-text)' }}>
            <Receipt className="w-4 h-4" />
            Credit Costs
          </h2>
          <div
            className="rounded border overflow-hidden"
            style={{ borderColor: 'var(--v-border)' }}
          >
            <table className="w-full text-xs">
              <thead>
                <tr style={{ backgroundColor: 'color-mix(in srgb, var(--v-surface) 50%, transparent)' }}>
                  <th className="text-left px-3 py-2 font-bold" style={{ color: 'var(--v-text-muted)' }}>Scan Type</th>
                  <th className="text-right px-3 py-2 font-bold" style={{ color: 'var(--v-text-muted)' }}>Credits</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(SCAN_COSTS).map(([path, cost]) => (
                  <tr key={path} className="border-t" style={{ borderColor: 'var(--v-border)' }}>
                    <td className="px-3 py-1.5" style={{ color: 'var(--v-text)' }}>
                      {SCAN_LABELS[path] || path}
                    </td>
                    <td className="px-3 py-1.5 text-right font-bold" style={{ color: 'var(--v-accent)' }}>
                      {cost}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Payment History */}
        <div>
          <h2 className="text-sm font-bold mb-3 flex items-center gap-2" style={{ color: 'var(--v-text)' }}>
            <CreditCard className="w-4 h-4" />
            Payment History
          </h2>
          {(!history || history.length === 0) ? (
            <div className="text-xs py-4 text-center" style={{ color: 'var(--v-text-muted)' }}>
              No payments yet
            </div>
          ) : (
            <div
              className="rounded border overflow-hidden"
              style={{ borderColor: 'var(--v-border)' }}
            >
              <table className="w-full text-xs">
                <thead>
                  <tr style={{ backgroundColor: 'color-mix(in srgb, var(--v-surface) 50%, transparent)' }}>
                    <th className="text-left px-3 py-2 font-bold" style={{ color: 'var(--v-text-muted)' }}>Date</th>
                    <th className="text-right px-3 py-2 font-bold" style={{ color: 'var(--v-text-muted)' }}>Amount</th>
                    <th className="text-right px-3 py-2 font-bold" style={{ color: 'var(--v-text-muted)' }}>Credits</th>
                    <th className="text-right px-3 py-2 font-bold" style={{ color: 'var(--v-text-muted)' }}>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {history.map((item) => (
                    <tr key={item.id} className="border-t" style={{ borderColor: 'var(--v-border)' }}>
                      <td className="px-3 py-1.5" style={{ color: 'var(--v-text)' }}>
                        {new Date(item.created_at).toLocaleDateString()}
                      </td>
                      <td className="px-3 py-1.5 text-right" style={{ color: 'var(--v-text)' }}>
                        ${item.amount.toFixed(2)}
                      </td>
                      <td className="px-3 py-1.5 text-right font-bold" style={{ color: 'var(--v-accent)' }}>
                        +{item.credits.toLocaleString()}
                      </td>
                      <td className="px-3 py-1.5 text-right">
                        <span
                          className="px-1.5 py-0.5 rounded text-[10px] uppercase"
                          style={{
                            backgroundColor: item.status === 'paid'
                              ? 'color-mix(in srgb, var(--v-success) 15%, transparent)'
                              : 'color-mix(in srgb, var(--v-text-muted) 15%, transparent)',
                            color: item.status === 'paid' ? 'var(--v-success)' : 'var(--v-text-muted)',
                          }}
                        >
                          {item.status}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </PageShell>
  );
}
