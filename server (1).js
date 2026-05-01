// ============================================================
//  admin-server.js — Standalone Admin Panel Server
//  Serves admin.html + all /admin/* API routes
// ============================================================

try { require('dotenv').config(); } catch(e) {}

const express = require('express');
const admin   = require('firebase-admin');
const path    = require('path');
const app     = express();
const PORT    = process.env.PORT || 3000;

app.use(express.json());

// ── CORS ────────────────────────────────────────────────────
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin-allow-popups');
    res.setHeader('Cross-Origin-Embedder-Policy', 'unsafe-none');
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    next();
});

// ── Firebase Admin ───────────────────────────────────────────
let db = null;
try {
    const raw = process.env.FIREBASE_SERVICE_ACCOUNT_JSON.trim();
    const sa  = JSON.parse(raw.startsWith('{') ? raw : Buffer.from(raw, 'base64').toString());
    if (sa.private_key) sa.private_key = sa.private_key.replace(/\\n/g, '\n');
    admin.initializeApp({ credential: admin.credential.cert(sa) });
    db = admin.firestore();
    console.log('Firebase Admin initialized');
} catch(e) {
    console.error('Firebase Admin init error:', e.message);
}

// ── Supabase REST client ─────────────────────────────────────
let supabase = null;
function initSupabase() {
    const url = process.env.SUPABASE_URL;
    const key = process.env.SUPABASE_SERVICE_KEY;
    if (!url || !key) { console.warn('Supabase not configured'); return; }
    supabase = { url: url.replace(/\/$/, ''), key };
    console.log('Supabase connected');
}
initSupabase();

async function sbQuery(table, { select='*', filters=[], order=null, limit=null, offset=null } = {}) {
    if (!supabase) throw new Error('Supabase not configured');
    let url = `${supabase.url}/rest/v1/${table}?select=${encodeURIComponent(select)}`;
    for (const f of filters) url += `&${f}`;
    if (order)  url += `&order=${order}`;
    if (limit  !== null) url += `&limit=${limit}`;
    if (offset !== null) url += `&offset=${offset}`;
    const res = await fetch(url, { headers: { apikey: supabase.key, Authorization: `Bearer ${supabase.key}`, 'Content-Type': 'application/json' } });
    if (!res.ok) throw new Error(`Supabase query failed: ${res.status} ${await res.text()}`);
    return res.json();
}
async function sbInsert(table, data) {
    if (!supabase) throw new Error('Supabase not configured');
    const res = await fetch(`${supabase.url}/rest/v1/${table}`, {
        method: 'POST',
        headers: { apikey: supabase.key, Authorization: `Bearer ${supabase.key}`, 'Content-Type': 'application/json', Prefer: 'return=representation' },
        body: JSON.stringify(data)
    });
    if (!res.ok) throw new Error(`Supabase insert failed: ${res.status} ${await res.text()}`);
    return res.json();
}
async function sbUpdate(table, match, data) {
    if (!supabase) throw new Error('Supabase not configured');
    const q = Object.entries(match).map(([k,v]) => `${k}=eq.${encodeURIComponent(v)}`).join('&');
    const res = await fetch(`${supabase.url}/rest/v1/${table}?${q}`, {
        method: 'PATCH',
        headers: { apikey: supabase.key, Authorization: `Bearer ${supabase.key}`, 'Content-Type': 'application/json', Prefer: 'return=representation' },
        body: JSON.stringify(data)
    });
    if (!res.ok) throw new Error(`Supabase update failed: ${res.status} ${await res.text()}`);
    return res.json();
}
async function sbDelete(table, match) {
    if (!supabase) throw new Error('Supabase not configured');
    const q = Object.entries(match).map(([k,v]) => `${k}=eq.${encodeURIComponent(v)}`).join('&');
    const res = await fetch(`${supabase.url}/rest/v1/${table}?${q}`, {
        method: 'DELETE',
        headers: { apikey: supabase.key, Authorization: `Bearer ${supabase.key}` }
    });
    if (!res.ok) throw new Error(`Supabase delete failed: ${res.status} ${await res.text()}`);
    return true;
}

// ── Auth middleware ──────────────────────────────────────────
async function requireAdmin(req, res, next) {
    if (!supabase) return res.status(503).json({ error: 'Supabase not configured' });
    const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
    if (!token) return res.status(401).json({ error: 'No token' });
    let uid, email;
    try {
        const decoded = await admin.auth().verifyIdToken(token);
        uid = decoded.uid; email = decoded.email;
    } catch(e) { return res.status(401).json({ error: 'Invalid token' }); }
    try {
        const rows = await sbQuery('admin_roles', { filters: [`uid=eq.${uid}`], limit: 1 });
        if (!rows || rows.length === 0) return res.status(403).json({ error: 'Not an admin' });
        req.adminUid = uid; req.adminEmail = email; req.adminRole = rows[0].role;
        sbUpdate('admin_roles', { uid }, { last_active: new Date().toISOString() }).catch(() => {});
        next();
    } catch(e) { res.status(500).json({ error: e.message }); }
}

async function auditLog(action, adminUid, targetUid, details = {}) {
    sbInsert('audit_logs', { action, admin_uid: adminUid, target_uid: targetUid || null, details: JSON.stringify(details), created_at: new Date().toISOString() }).catch(() => {});
}

// ── Health ───────────────────────────────────────────────────
app.get('/health', (_, res) => res.json({ ok: true, supabase: !!supabase }));

// ── Admin Routes ─────────────────────────────────────────────
app.get('/admin/team', requireAdmin, async (req, res) => {
    try { res.json({ team: await sbQuery('admin_roles', { order: 'created_at.desc' }), role: req.adminRole }); }
    catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/admin/team', requireAdmin, async (req, res) => {
    if (req.adminRole !== 'super_admin') return res.status(403).json({ error: 'super_admin only' });
    const { uid, email, displayName, role } = req.body;
    try { await sbInsert('admin_roles', { uid, email, display_name: displayName||'', role, added_by: req.adminUid }); await auditLog('team.add', req.adminUid, uid, { email, role }); res.json({ ok: true }); }
    catch(e) { res.status(500).json({ error: e.message }); }
});
app.delete('/admin/team/:uid', requireAdmin, async (req, res) => {
    if (req.adminRole !== 'super_admin') return res.status(403).json({ error: 'super_admin only' });
    try { await sbDelete('admin_roles', { uid: req.params.uid }); await auditLog('team.remove', req.adminUid, req.params.uid); res.json({ ok: true }); }
    catch(e) { res.status(500).json({ error: e.message }); }
});
app.get('/admin/stats/overview', requireAdmin, async (req, res) => {
    try {
        const [users, banned, dau, msg] = await Promise.all([
            sbQuery('users_mirror', { select:'uid', filters:['is_deleted=eq.false'] }),
            sbQuery('users_mirror', { select:'uid', filters:['is_banned=eq.true'] }),
            sbQuery('daily_active_users', { select:'uid', filters:[`active_date=eq.${new Date().toISOString().slice(0,10)}`] }),
            sbQuery('message_stats', { select:'total_messages', order:'stat_date.desc', limit:1 })
        ]);
        res.json({ totalUsers: users.length, bannedUsers: banned.length, dauToday: dau.length, totalMessages: msg[0]?.total_messages||0 });
    } catch(e) { res.status(500).json({ error: e.message }); }
});
app.get('/admin/stats/messages', requireAdmin, async (req, res) => {
    try { res.json({ data: await sbQuery('message_stats_daily', { order:'stat_date.desc', limit:30 }) }); }
    catch(e) { res.status(500).json({ error: e.message }); }
});
app.get('/admin/stats/dau', requireAdmin, async (req, res) => {
    try { res.json({ data: await sbQuery('dau_counts', { order:'active_date.desc', limit:30 }) }); }
    catch(e) { res.status(500).json({ error: e.message }); }
});
app.get('/admin/stats/features', requireAdmin, async (req, res) => {
    try { res.json({ data: await sbQuery('feature_stats', { order:'stat_date.desc', limit:7 }) }); }
    catch(e) { res.status(500).json({ error: e.message }); }
});
app.get('/admin/users', requireAdmin, async (req, res) => {
    const page=parseInt(req.query.page)||0, pageSize=20, search=(req.query.search||'').trim(), filter=req.query.filter||'';
    try {
        let filters=['is_deleted=eq.false'];
        if (filter==='banned') filters.push('is_banned=eq.true');
        if (search) filters.push(`or=(email.ilike.*${search}*,display_name.ilike.*${search}*,uid.ilike.*${search}*)`);
        const rows = await sbQuery('users_mirror', { select:'uid,email,display_name,photo_url,created_at,last_seen,is_banned,ban_reason,ban_expires_at,totp_enabled,friend_count,group_count', filters, order:'created_at.desc', limit:pageSize, offset:page*pageSize });
        res.json({ users: rows, page, hasMore: rows.length===pageSize });
    } catch(e) { res.status(500).json({ error: e.message }); }
});
app.get('/admin/users/:uid', requireAdmin, async (req, res) => {
    try {
        const [users, notes, logs] = await Promise.all([
            sbQuery('users_mirror', { filters:[`uid=eq.${req.params.uid}`], limit:1 }),
            sbQuery('admin_notes', { filters:[`target_uid=eq.${req.params.uid}`], order:'created_at.desc', limit:20 }),
            sbQuery('login_logs', { filters:[`uid=eq.${req.params.uid}`], order:'created_at.desc', limit:10 })
        ]);
        if (!users.length) return res.status(404).json({ error: 'User not found' });
        res.json({ user: users[0], notes, loginLogs: logs });
    } catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/admin/users/:uid/note', requireAdmin, async (req, res) => {
    try { await sbInsert('admin_notes', { target_uid:req.params.uid, admin_uid:req.adminUid, note:req.body.note }); await auditLog('user.note', req.adminUid, req.params.uid); res.json({ ok:true }); }
    catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/admin/users/:uid/ban', requireAdmin, async (req, res) => {
    const { reason, expiresAt } = req.body;
    try {
        await sbUpdate('users_mirror', { uid:req.params.uid }, { is_banned:true, ban_reason:reason||'Violation', ban_expires_at:expiresAt||null, banned_by:req.adminUid, banned_at:new Date().toISOString() });
        if (db) admin.auth().updateUser(req.params.uid, { disabled:true }).catch(()=>{});
        await auditLog('user.ban', req.adminUid, req.params.uid, { reason });
        res.json({ ok:true });
    } catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/admin/users/:uid/unban', requireAdmin, async (req, res) => {
    try {
        await sbUpdate('users_mirror', { uid:req.params.uid }, { is_banned:false, ban_reason:null, ban_expires_at:null, banned_by:null, banned_at:null });
        if (db) admin.auth().updateUser(req.params.uid, { disabled:false }).catch(()=>{});
        await auditLog('user.unban', req.adminUid, req.params.uid);
        res.json({ ok:true });
    } catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/admin/users/:uid/force-logout', requireAdmin, async (req, res) => {
    try {
        await sbUpdate('sessions', { uid:req.params.uid }, { force_logout:true, is_active:false });
        if (db) admin.auth().revokeRefreshTokens(req.params.uid).catch(()=>{});
        await auditLog('user.force_logout', req.adminUid, req.params.uid);
        res.json({ ok:true });
    } catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/admin/users/:uid/reset-totp', requireAdmin, async (req, res) => {
    try {
        if (db) await db.collection('users').doc(req.params.uid).update({ totpEnabled:false, totpSecret:admin.firestore.FieldValue.delete(), totpSecretPending:admin.firestore.FieldValue.delete() });
        await auditLog('user.reset_totp', req.adminUid, req.params.uid);
        res.json({ ok:true });
    } catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/admin/users/:uid/send-alert', requireAdmin, async (req, res) => {
    const { title, message, alertType } = req.body;
    try { await sbInsert('admin_alerts', { uid:req.params.uid, title, message, alert_type:alertType||'info', sent_by:req.adminUid, created_at:new Date().toISOString() }); res.json({ ok:true }); }
    catch(e) { res.status(500).json({ error: e.message }); }
});
app.get('/admin/reports', requireAdmin, async (req, res) => {
    try { res.json({ reports: await sbQuery('pending_reports_view', { order:'created_at.desc', limit:50 }) }); }
    catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/admin/reports/:id/action', requireAdmin, async (req, res) => {
    try {
        await sbUpdate('reports', { id:req.params.id }, { status:req.body.action==='dismiss'?'dismissed':'resolved', resolved_by:req.adminUid, resolved_at:new Date().toISOString() });
        res.json({ ok:true });
    } catch(e) { res.status(500).json({ error: e.message }); }
});
app.get('/admin/security/login-logs', requireAdmin, async (req, res) => {
    const page=parseInt(req.query.page)||0, pageSize=25, suspicious=req.query.suspicious==='true';
    try {
        const filters=suspicious?['is_suspicious=eq.true']:[];
        res.json({ logs: await sbQuery('login_logs', { select:'id,uid,email,ip_address,device_type,os,browser,country,city,is_suspicious,suspicion_reason,created_at', filters, order:'created_at.desc', limit:pageSize, offset:page*pageSize }), page });
    } catch(e) { res.status(500).json({ error: e.message }); }
});
app.get('/admin/security/sessions', requireAdmin, async (req, res) => {
    try { res.json({ sessions: await sbQuery('active_sessions_view', { limit:100 }) }); }
    catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/admin/sessions/:id/logout', requireAdmin, async (req, res) => {
    try { await sbUpdate('sessions', { id:req.params.id }, { force_logout:true, is_active:false }); res.json({ ok:true }); }
    catch(e) { res.status(500).json({ error: e.message }); }
});
app.get('/admin/security/ip-blacklist', requireAdmin, async (req, res) => {
    try { res.json({ blacklist: await sbQuery('ip_blacklist', { order:'created_at.desc' }) }); }
    catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/admin/security/ip-blacklist', requireAdmin, async (req, res) => {
    try { await sbInsert('ip_blacklist', { ip_address:req.body.ipAddress, reason:req.body.reason, added_by:req.adminUid }); res.json({ ok:true }); }
    catch(e) { res.status(500).json({ error: e.message }); }
});
app.delete('/admin/security/ip-blacklist/:ip', requireAdmin, async (req, res) => {
    try { await sbDelete('ip_blacklist', { ip_address:req.params.ip }); res.json({ ok:true }); }
    catch(e) { res.status(500).json({ error: e.message }); }
});
app.get('/admin/flags', requireAdmin, async (req, res) => {
    try { res.json({ flags: await sbQuery('feature_flags') }); }
    catch(e) { res.status(500).json({ error: e.message }); }
});
app.patch('/admin/flags/:key', requireAdmin, async (req, res) => {
    if (req.adminRole !== 'super_admin') return res.status(403).json({ error: 'super_admin only' });
    try { await sbUpdate('feature_flags', { key:req.params.key }, { value:req.body.value, updated_by:req.adminUid, updated_at:new Date().toISOString() }); res.json({ ok:true }); }
    catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/admin/broadcast', requireAdmin, async (req, res) => {
    const { title, message, channel } = req.body;
    try { await sbInsert('broadcasts', { title, message, channel:channel||'all', sent_by:req.adminUid, created_at:new Date().toISOString() }); res.json({ ok:true }); }
    catch(e) { res.status(500).json({ error: e.message }); }
});
app.get('/admin/audit-logs', requireAdmin, async (req, res) => {
    const page=parseInt(req.query.page)||0, pageSize=30;
    try { res.json({ logs: await sbQuery('audit_logs', { order:'created_at.desc', limit:pageSize, offset:page*pageSize }), page }); }
    catch(e) { res.status(500).json({ error: e.message }); }
});

// ── Serve admin panel static files ───────────────────────────
app.use(express.static(path.join(__dirname)));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.listen(PORT, () => console.log(`Admin server running on port ${PORT}`));
