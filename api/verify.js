// License app project: api/verify.js (replaces the earlier version)
// Env vars: TURSO_URL (https form), TURSO_TOKEN (full access, it writes last_check), VERIFY_SECRET

export default async function handler(req, res) {
  try { return await main(req, res); }
  catch (e) { return res.status(500).json({ valid: false, reason: 'server_error', detail: String(e.message || e) }); }
}

async function main(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-verify-secret');
  if (req.method === 'OPTIONS') return res.status(204).end();

  const src = req.method === 'POST' ? (req.body || {}) : req.query;
  const key = String(src.key || '').trim().toUpperCase();
  if (!key) return res.status(400).json({ valid: false, reason: 'missing_key' });

  const run = async (sql, args) => {
    const r = await fetch(process.env.TURSO_URL + '/v2/pipeline', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + process.env.TURSO_TOKEN, 'Content-Type': 'application/json' },
      body: JSON.stringify({ requests: [
        { type: 'execute', stmt: { sql, args: args.map(v => ({ type: 'text', value: v })) } },
        { type: 'close' }
      ] })
    });
    const j = await r.json();
    const x = j.results && j.results[0];
    if (!x || x.type === 'error') throw new Error('Turso: ' + (x ? x.error.message : (j.message || r.status)));
    return x.response.result.rows;
  };

  const rows = await run('SELECT url,status,expires_at FROM licenses WHERE key=?', [key]);
  if (!rows.length) return res.json({ valid: false, reason: 'not_found' });
  const [url, status, exp] = rows[0].map(c => c.value);

  // Server-to-server calls (portal middleware) send the secret and the real host.
  // Browser calls fall back to the Origin header.
  const trusted = process.env.VERIFY_SECRET && req.headers['x-verify-secret'] === process.env.VERIFY_SECRET;
  let host = '';
  if (trusted) host = String(src.host || '');
  else if (req.headers.origin) { try { host = new URL(req.headers.origin).host; } catch (e) {} }

  const hostOk = !!host && url.split(',').some(u => { try { return new URL(u.trim()).host === host; } catch (e) { return false; } });
  const expired = exp && exp < new Date().toISOString().slice(0, 10);
  const valid = status === 'active' && !expired && hostOk;

  if (valid) { try { await run('UPDATE licenses SET last_check=?, last_host=?, checks=COALESCE(checks,0)+1 WHERE key=?', [new Date().toISOString(), host, key]); } catch (e) {} }
  res.json({ valid, reason: valid ? 'ok' : status !== 'active' ? status : expired ? 'expired' : 'wrong_site' });
}
