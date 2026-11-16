/****************************************************************
 Name:     CLD - Environment File (.env) Disclosure
 Author:   CLD
 Severity: critical
 Type:     target script (runs once per target)

 Looks for exposed environment / secrets files:
   /.env  /.env.backup  /.env.bak  /.env.old  /.env.save  /.env~
   /.env.example  /example.env  /.env.sample  /.env.dist
   /.env.local  /.env.production  /.env.prod  /.env.dev  /.env.staging ...
   + the same in common sub-folders (/api/ /app/ /backend/ /laravel/ ...)
 Max 100 requests, most likely names first.

 A hit needs HTTP 200, non-HTML, body > 20 bytes AND real proof:
   - at least 3 lines in KEY=VALUE form
   - and at least one known config key (APP_KEY, DB_PASSWORD,
     DATABASE_URL, AWS_*, MAIL_*, REDIS_*, JWT_SECRET, *_SECRET, *_API_KEY ...)
 Catch-all guard: a random /.env.<random> is requested first; if it
 also looks like a .env file the target is skipped (no false positives).
 Reports each distinct file found (max 5 alerts) and says whether
 it holds real secret values or only template / placeholder values.
 ****************************************************************/

const CLD_MAX = 100;
const CLD_MAX_ALERTS = 5;

const CLD_NAMES = [
    '.env', '.env.backup', '.env.bak', '.env.old', '.env.save', '.env~', '.env.orig', '.env.copy',
    '.env.example', 'example.env', '.env.sample', '.env.dist', '.env.template',
    '.env.local', '.env.production', '.env.prod', '.env.dev', '.env.development',
    '.env.staging', '.env.stage', '.env.test', '.env.live', '.env.txt', '.env.1',
    '.env_backup', '.env-backup', '.env.bk', '.env.swp', 'env', 'env.txt', 'env.bak',
    'env.example', 'backup.env', 'production.env', 'prod.env', 'dev.env', 'local.env', '.env.docker'
];
const CLD_DIRS = ['api', 'app', 'backend', 'laravel', 'src', 'public', 'web', 'core', 'server',
                  'admin', 'config', 'docker', 'site', 'www', 'project', 'application'];

function cldBuildPaths() {
    let list = [];
    let add = p => { if (list.indexOf(p) === -1) list.push(p); };
    // 1. every name in the web root
    CLD_NAMES.forEach(n => add(`/${n}`));
    // 2. the top names in common sub-folders
    CLD_DIRS.forEach(d => ['.env', '.env.backup', '.env.example', '.env.bak'].forEach(n => add(`/${d}/${n}`)));
    return list.slice(0, CLD_MAX - 1);   // 1 request reserved for the catch-all guard
}

const CLD_PATHS = cldBuildPaths();

// --- matchers ---
const CLD_KEY_LINE = /^\s*(export\s+)?[A-Z][A-Z0-9_]{1,63}\s*=.*$/gm;
const CLD_KNOWN_KEY = /^\s*(export\s+)?(APP_KEY|APP_SECRET|APP_ENV|APP_DEBUG|APP_URL|SECRET_KEY|DJANGO_SECRET_KEY|DB_(HOST|USER(NAME)?|PASS(WORD)?|DATABASE|NAME|CONNECTION|PORT)|DATABASE_URL|MONGO(DB)?_(URI|URL)|REDIS_(HOST|PASSWORD|URL)|MAIL_(HOST|USERNAME|PASSWORD)|SMTP_(HOST|USER|PASS(WORD)?)|AWS_(ACCESS_KEY_ID|SECRET_ACCESS_KEY|DEFAULT_REGION|BUCKET)|JWT_SECRET|STRIPE_(KEY|SECRET)|SENTRY_DSN|PUSHER_APP_(KEY|SECRET)|[A-Z0-9_]*_(SECRET|API_KEY|TOKEN|PASSWORD))\s*=/m;
const CLD_SECRET_KEY = /^[ \t]*(export[ \t]+)?([A-Z0-9_]*(PASSWORD|PASS|SECRET|_KEY|TOKEN|DSN)|DATABASE_URL|MONGO(DB)?_(URI|URL)|REDIS_URL)[ \t]*=[ \t]*["']?([^"'\s#]*)/gm;
const CLD_PLACEHOLDER = /^(|null|none|changeme|change_me|secret|password|your[_-]?.*|xxx+|\*+|<.*>|\$\{.*\}|example.*|test|root|base64:)$/i;

function cldParse(body) {
    let lines = body.match(CLD_KEY_LINE) || [];
    if (lines.length < 3 || !CLD_KNOWN_KEY.test(body)) return null;

    let secrets = [], m;
    CLD_SECRET_KEY.lastIndex = 0;
    while ((m = CLD_SECRET_KEY.exec(body)) !== null) {
        if (!CLD_PLACEHOLDER.test(m[6] || '')) secrets.push(m[2]);   // m[6] = the value
    }
    let keys = lines.map(l => l.trim().replace(/^export\s+/, '').split('=')[0].trim());
    return { lines: lines.length, keys: keys.filter((k, i) => keys.indexOf(k) === i), secrets: secrets.filter((k, i) => secrets.indexOf(k) === i) };
}

function cldProbe(path) {
    let job = ax.http.job();
    job.hostname = scriptArg.target.host;
    job.port = scriptArg.target.port;
    job.secure = scriptArg.target.secure;
    job.request.uri = path;
    ax.http.execute(job).sync();
    return job;
}

function cldCheck(job) {
    if (job.error || !job.response || job.response.status !== 200) return null;
    let ctype = job.response.headers.has('Content-Type') ? job.response.headers.get('Content-Type') : '';
    if (ctype.toLowerCase().indexOf('text/html') !== -1) return null;
    let body = job.response.body || '';
    if (body.length <= 20 || /^\s*</.test(body)) return null;
    return cldParse(body);
}

// --- catch-all guard ---
let cldRandom = '/.env.cld' + Math.floor(Math.random() * 1e9).toString(36);
if (cldCheck(cldProbe(cldRandom))) {
    ax.log(ax.LogLevelInfo, `[CLD] .env check skipped: server answers every .env path (${cldRandom})`);
} else {
    let alerts = 0, seen = [];
    for (let i = 0; i < CLD_PATHS.length && alerts < CLD_MAX_ALERTS; i++) {
        let job = cldProbe(CLD_PATHS[i]);
        let r = cldCheck(job);
        if (!r) continue;

        // same file served under several names -> report once
        let sig = (job.response.body || '').length + ':' + r.keys.join(',');
        if (seen.indexOf(sig) !== -1) continue;
        seen.push(sig);
        alerts++;

        let real = r.secrets.length > 0;
        ax.log(ax.LogLevelInfo, `[CLD] .env file exposed at ${CLD_PATHS[i]} (${real ? 'real secrets' : 'template'})`);
        scanState.addVuln({
            typeId: 'custom.xml',
            path: CLD_PATHS[i],
            http: job,
            details: `[b]CLD - Environment File (.env) Disclosure[/b][break]` +
                     `Path: [code]${CLD_PATHS[i]}[/code][break]` +
                     `Contains real secret values: [code]${real ? 'YES - ' + ax.util.htmlEncode(r.secrets.slice(0, 15).join(', ')) : 'no (template / placeholder values)'}[/code][break]` +
                     `Config lines: [code]${r.lines}[/code][break]` +
                     `Keys: [code]${ax.util.htmlEncode(r.keys.slice(0, 25).join(', '))}[/code]`
        });
    }
}
