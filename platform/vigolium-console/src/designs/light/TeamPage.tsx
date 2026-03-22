'use client';

import { useState } from 'react';
import { Users, Mail, Trash2, Github, Unplug } from 'lucide-react';
import { useTeamMembers, useInviteMember, useRemoveMember, useCurrentUser, useGitHubStatus, useGitHubDisconnect } from '@/api/hooks';
import { useToast } from '@/contexts/ToastContext';
import PageShell from './PageShell';

export default function TeamPage() {
  const { data: members, isLoading } = useTeamMembers();
  const { data: currentUser } = useCurrentUser();
  const invite = useInviteMember();
  const remove = useRemoveMember();
  const { toast } = useToast();
  const [email, setEmail] = useState('');

  const handleInvite = async () => {
    if (!email.trim()) return;
    try {
      await invite.mutateAsync({ email: email.trim() });
      toast(`Invitation sent to ${email}`, 'success');
      setEmail('');
    } catch (err) {
      toast(err instanceof Error ? err.message : 'Failed to invite', 'error');
    }
  };

  const handleRemove = async (membershipId: string, name: string) => {
    if (!confirm(`Remove ${name} from the team?`)) return;
    try {
      await remove.mutateAsync(membershipId);
      toast(`${name} removed`, 'success');
    } catch (err) {
      toast(err instanceof Error ? err.message : 'Failed to remove', 'error');
    }
  };

  return (
    <PageShell>
      <div className="p-4 max-w-4xl mx-auto space-y-4">
        <div className="flex items-center gap-2 mb-2">
          <Users className="w-4 h-4" style={{ color: 'var(--v-secondary)' }} />
          <h2 className="text-sm font-bold" style={{ color: 'var(--v-accent)' }}>
            Team{currentUser?.organization ? ` — ${currentUser.organization.name}` : ''}
          </h2>
        </div>

        {/* Invite */}
        <div className="flex items-center gap-2">
          <Mail className="w-3 h-3" style={{ color: 'var(--v-text-muted)' }} />
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleInvite()}
            placeholder="email@example.com"
            className="flex-1 px-2 py-1 text-xs border outline-none"
            style={{ backgroundColor: 'var(--v-bg)', borderColor: 'var(--v-border)', color: 'var(--v-text)' }}
          />
          <button
            onClick={handleInvite}
            disabled={invite.isPending || !email.trim()}
            className="px-3 py-1 text-xs font-bold border transition-colors"
            style={{ borderColor: 'var(--v-accent)', color: 'var(--v-accent)' }}
          >
            {invite.isPending ? 'Sending...' : 'Invite'}
          </button>
        </div>

        {/* Members */}
        <div className="border overflow-hidden" style={{ borderColor: 'var(--v-border)' }}>
          <table className="w-full text-xs">
            <thead>
              <tr style={{ backgroundColor: 'color-mix(in srgb, var(--v-surface) 50%, transparent)' }}>
                <th className="text-left px-3 py-2 font-bold" style={{ color: 'var(--v-text-muted)' }}>Name</th>
                <th className="text-left px-3 py-2 font-bold" style={{ color: 'var(--v-text-muted)' }}>Email</th>
                <th className="text-left px-3 py-2 font-bold" style={{ color: 'var(--v-text-muted)' }}>Role</th>
                <th className="text-left px-3 py-2 font-bold" style={{ color: 'var(--v-text-muted)' }}>Joined</th>
                <th className="w-8"></th>
              </tr>
            </thead>
            <tbody>
              {isLoading && (
                <tr><td colSpan={5} className="px-3 py-4 text-center" style={{ color: 'var(--v-text-muted)' }}>Loading...</td></tr>
              )}
              {members?.map((m) => (
                <tr key={m.id} className="border-t" style={{ borderColor: 'var(--v-border)' }}>
                  <td className="px-3 py-1.5" style={{ color: 'var(--v-text)' }}>{m.name}</td>
                  <td className="px-3 py-1.5" style={{ color: 'var(--v-text-muted)' }}>{m.email}</td>
                  <td className="px-3 py-1.5">
                    <span
                      className="px-1.5 py-0.5 text-[10px] uppercase rounded"
                      style={{
                        backgroundColor: m.role === 'admin'
                          ? 'color-mix(in srgb, var(--v-accent) 15%, transparent)'
                          : 'color-mix(in srgb, var(--v-text-muted) 15%, transparent)',
                        color: m.role === 'admin' ? 'var(--v-accent)' : 'var(--v-text-muted)',
                      }}
                    >
                      {m.role}
                    </span>
                  </td>
                  <td className="px-3 py-1.5" style={{ color: 'var(--v-text-muted)' }}>
                    {new Date(m.joined_at).toLocaleDateString()}
                  </td>
                  <td className="px-3 py-1.5">
                    {m.email !== currentUser?.email && (
                      <button
                        onClick={() => handleRemove(m.membership_id, m.name)}
                        className="transition-colors"
                        style={{ color: 'var(--v-error)' }}
                        title="Remove member"
                      >
                        <Trash2 className="w-3 h-3" />
                      </button>
                    )}
                  </td>
                </tr>
              ))}
              {!isLoading && (!members || members.length === 0) && (
                <tr><td colSpan={5} className="px-3 py-4 text-center" style={{ color: 'var(--v-text-muted)' }}>No team members</td></tr>
              )}
            </tbody>
          </table>
        </div>
        {/* GitHub Connection */}
        <GitHubSection />
      </div>
    </PageShell>
  );
}

function GitHubSection() {
  const { data: status } = useGitHubStatus();
  const disconnect = useGitHubDisconnect();
  const { toast } = useToast();

  const handleDisconnect = async () => {
    if (!confirm('Disconnect GitHub?')) return;
    try {
      await disconnect.mutateAsync();
      toast('GitHub disconnected', 'success');
    } catch (err) {
      toast(err instanceof Error ? err.message : 'Failed to disconnect', 'error');
    }
  };

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <Github className="w-4 h-4" style={{ color: 'var(--v-secondary)' }} />
        <h2 className="text-sm font-bold" style={{ color: 'var(--v-accent)' }}>GitHub</h2>
      </div>
      <div
        className="flex items-center justify-between px-3 py-2 border rounded text-xs"
        style={{ borderColor: 'var(--v-border)' }}
      >
        {status?.connected ? (
          <>
            <span style={{ color: 'var(--v-success)' }}>
              Connected (installation #{status.installation_id})
            </span>
            <button
              onClick={handleDisconnect}
              className="flex items-center gap-1 transition-colors"
              style={{ color: 'var(--v-error)' }}
            >
              <Unplug className="w-3 h-3" /> Disconnect
            </button>
          </>
        ) : (
          <>
            <span style={{ color: 'var(--v-text-muted)' }}>Not connected</span>
            <a
              href="/api/github/install"
              className="flex items-center gap-1 px-2 py-0.5 border rounded transition-colors"
              style={{ borderColor: 'var(--v-accent)', color: 'var(--v-accent)' }}
            >
              <Github className="w-3 h-3" /> Connect GitHub
            </a>
          </>
        )}
      </div>
    </div>
  );
}
