import React, { useEffect, useMemo, useState } from 'react';
import { useAuth } from '../../context/AuthContext';

const AdminIPControl = () => {
  const { authFetch } = useAuth();
  const [blocked, setBlocked] = useState([]);
  const [loading, setLoading] = useState(true);
  const [adding, setAdding] = useState(false);
  const [ip, setIp] = useState('');
  const [reason, setReason] = useState('Blocked by admin');
  const [notice, setNotice] = useState('');

  const stats = useMemo(() => ({ total: blocked.length }), [blocked]);

  const loadBlocked = async () => {
    setLoading(true);
    try {
      const res = await authFetch('/api/ip-control/blocked');
      if (!res.ok) {
        setBlocked([]);
        return;
      }
      setBlocked(await res.json());
    } catch (err) {
      console.error('Failed to load blocked IPs', err);
      setBlocked([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadBlocked();
    const interval = setInterval(loadBlocked, 10000);
    return () => clearInterval(interval);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const addBlockedIp = async (e) => {
    e.preventDefault();
    if (!ip.trim()) return;

    setAdding(true);
    setNotice('');
    try {
      const res = await authFetch('/api/ip-control/blocked', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip.trim(), reason: reason.trim() || 'Blocked by admin' }),
      });
      if (!res.ok) {
        setNotice('Block action failed');
        return;
      }
      setNotice(`Blocked ${ip.trim()}`);
      setIp('');
      setReason('Blocked by admin');
      await loadBlocked();
    } catch (err) {
      console.error('Failed to block IP', err);
      setNotice('Block action failed due to network/server error');
    } finally {
      setAdding(false);
    }
  };

  const unblockIp = async (targetIp) => {
    const ok = window.confirm(`Allow access again for ${targetIp}?`);
    if (!ok) return;

    setNotice('');
    try {
      const res = await authFetch(`/api/ip-control/blocked/${encodeURIComponent(targetIp)}`, {
        method: 'DELETE',
      });
      if (!res.ok) {
        setNotice(`Failed to unblock ${targetIp}`);
        return;
      }
      setNotice(`Unblocked ${targetIp}`);
      await loadBlocked();
    } catch (err) {
      console.error('Failed to unblock IP', err);
      setNotice('Unblock action failed due to network/server error');
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
        <span className="badge" style={{ background: 'rgba(239,68,68,0.15)', color: '#fca5a5' }}>
          Blocked IPs: {stats.total}
        </span>
      </div>

      <form onSubmit={addBlockedIp} style={{ display: 'grid', gridTemplateColumns: '1.2fr 2fr auto', gap: '0.75rem' }}>
        <input
          value={ip}
          onChange={(e) => setIp(e.target.value)}
          placeholder="IP address to block"
          required
        />
        <input
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="Reason"
        />
        <button type="submit" disabled={adding}>{adding ? 'Blocking...' : 'Block IP'}</button>
      </form>

      {notice && (
        <div style={{
          fontSize: '0.85rem',
          background: 'rgba(8, 12, 20, 0.85)',
          border: '1px solid var(--panel-border)',
          borderRadius: '8px',
          padding: '0.75rem',
          color: 'var(--text-primary)',
        }}>
          {notice}
        </div>
      )}

      <div className="table-container" style={{ maxHeight: '280px', overflowY: 'auto' }}>
        <table>
          <thead style={{ position: 'sticky', top: 0, background: 'rgba(22, 30, 46, 0.95)', zIndex: 1 }}>
            <tr>
              <th>IP</th>
              <th>Reason</th>
              <th>Blocked By</th>
              <th>Blocked At</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan="5" style={{ textAlign: 'center', padding: '1rem' }}>Loading blocked IPs...</td>
              </tr>
            ) : blocked.length === 0 ? (
              <tr>
                <td colSpan="5" style={{ textAlign: 'center', padding: '1rem', color: 'var(--text-muted)' }}>
                  No blocked IPs.
                </td>
              </tr>
            ) : (
              blocked.map((row) => (
                <tr key={row.ip}>
                  <td style={{ fontFamily: 'monospace' }}>{row.ip}</td>
                  <td>{row.reason || '-'}</td>
                  <td>{row.blocked_by || '-'}</td>
                  <td className="text-muted text-sm">{row.blocked_at ? new Date(row.blocked_at).toLocaleString() : '-'}</td>
                  <td>
                    <button className="secondary" onClick={() => unblockIp(row.ip)}>Allow Access</button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default AdminIPControl;
