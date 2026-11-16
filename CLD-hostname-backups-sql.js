/****************************************************************
 Name:     CLD - SQL Dump / Database File Disclosure
 Author:   CLD
 Severity: critical
 Type:     target script (runs once per target)

 Looks for exposed SQL dumps and database files. Max 100 requests,
 most likely names first:
   1. generic names in web root   /dump.sql /data.sql /backup.sql /db.sql ...
   2. generic names in backup dirs /backup/ /backups/ /db/ /sql/ /dump/
   3. names built from the host    /www.example.com.sql /example.com.sql /example.sql
   4. compressed + SQLite variants .sql.gz .sql.zip .sqlite .sqlite3 .db

 A hit needs HTTP 200, a non-HTML response, body > 64 bytes AND real proof:
   - SQL dump header (mysqldump, MariaDB, phpMyAdmin, pg_dump, Adminer)
   - or line-start CREATE TABLE / DROP TABLE / INSERT INTO statements
   - or a mysqldump "/*!40101 SET" directive
   - or binary signature: gzip, ZIP, PostgreSQL custom dump (PGDMP), SQLite
 Stops at the first match.
 ****************************************************************/

const CLD_MAX = 100;

// --- host name variants: www.example.com -> www.example.com, example.com, example ---
function cldHostVariants(host) {
    host = String(host).toLowerCase().replace(/:\d+$/, '');
    if (/^[\d.]+$/.test(host) || host.indexOf(':') !== -1) return [host];   // IPv4 / IPv6
    let out = [host];
    let bare = host.replace(/^www\d*\./, '');
    out.push(bare);
    let p = bare.split('.');
    if (p.length >= 2) {
        // example.co.uk -> example ; example.com -> example
        let sld = (p.length >= 3 && p[p.length - 1].length === 2 && p[p.length - 2].length <= 3) ? p[p.length - 3] : p[p.length - 2];
        out.push(sld);
    }
    return out.filter((v, i) => v && out.indexOf(v) === i);
}

const CLD_HOSTS = cldHostVariants(scriptArg.target.host);

const CLD_GENERIC_TOP = ['dump', 'data', 'backup', 'db', 'database', 'db_backup', 'mysql', 'site'];
const CLD_GENERIC_MORE = ['sql', 'export', 'database_backup', 'backup_db', 'dbdump', 'db_dump', 'www',
                          'users', 'wordpress', 'wp', 'localhost', 'latest', 'prod', 'production', '1'];

function cldBuildPaths() {
    let list = [];
    let add = p => { if (list.indexOf(p) === -1) list.push(p); };

    // 1. generic, web root, plain .sql
    CLD_GENERIC_TOP.concat(CLD_GENERIC_MORE).forEach(n => add(`/${n}.sql`));
    // 2. host-based, web root, plain .sql
    CLD_HOSTS.forEach(h => ['', '_db', '_backup', '-backup', '_dump'].forEach(s => add(`/${h}${s}.sql`)));
    // 3. generic names in backup dirs
    ['/backup/', '/backups/', '/db/', '/sql/', '/dump/'].forEach(d =>
        ['dump', 'data', 'backup', 'db', 'database'].forEach(n => add(`${d}${n}.sql`)));
    // 4. compressed variants of the top names
    CLD_GENERIC_TOP.forEach(n => { add(`/${n}.sql.gz`); add(`/${n}.sql.zip`); });
    CLD_HOSTS.forEach(h => { add(`/${h}.sql.gz`); add(`/${h}.sql.zip`); });
    // 5. SQLite / other dump files
    ['/database.sqlite', '/db.sqlite', '/db.sqlite3', '/data.db', '/database.db', '/dump.pgsql', '/dump.psql', '/db.dump'].forEach(add);
    // 6. host-based in backup dir
    CLD_HOSTS.forEach(h => { add(`/backup/${h}.sql`); add(`/backups/${h}.sql`); });

    return list.slice(0, CLD_MAX);
}

const CLD_PATHS = cldBuildPaths();

// --- matchers ---
const CLD_SQL_PATTERNS = [
    [/^-- (MySQL|MariaDB) dump/m, 'mysqldump header'],
    [/^-- phpMyAdmin SQL Dump/m, 'phpMyAdmin dump header'],
    [/^-- (PostgreSQL database dump|Dumped from database version)/m, 'pg_dump header'],
    [/^-- Adminer [\d.]+ (MySQL|PostgreSQL)/m, 'Adminer dump header'],
    [/^\/\*!40\d{3} SET /m, 'mysqldump SET directive'],
    [/^(DROP TABLE( IF EXISTS)?|CREATE TABLE( IF NOT EXISTS)?)\s+[`"\[]?\w+/mi, 'CREATE/DROP TABLE statement'],
    [/^INSERT INTO\s+[`"\[]?\w+[`"\]]?\s*(\(|VALUES)/mi, 'INSERT INTO statement']
];

function cldByte(body, i, code) {
    let c = body.charCodeAt(i);
    return c === code || c === 0xFFFD;   // non-ASCII bytes may arrive as U+FFFD
}

function cldMatch(body) {
    for (let i = 0; i < CLD_SQL_PATTERNS.length; i++) {
        let m = body.match(CLD_SQL_PATTERNS[i][0]);
        if (m) return CLD_SQL_PATTERNS[i][1] + ': ' + m[0].substring(0, 80);
    }
    if (body.startsWith('SQLite format 3\x00')) return 'SQLite database file';
    if (body.startsWith('PGDMP')) return 'PostgreSQL custom-format dump (PGDMP)';
    if (body.startsWith('PK\x03\x04')) return 'ZIP archive';
    if (body.charCodeAt(0) === 0x1f && cldByte(body, 1, 0x8b)) return 'gzip archive';
    return null;
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

for (let i = 0; i < CLD_PATHS.length; i++) {
    let job = cldProbe(CLD_PATHS[i]);
    if (job.error || job.response.status !== 200) continue;

    let ctype = job.response.headers.has('Content-Type') ? job.response.headers.get('Content-Type') : '';
    if (ctype.toLowerCase().indexOf('text/html') !== -1) continue;

    let body = job.response.body || '';
    if (body.length <= 64) continue;

    let evidence = cldMatch(body);
    if (!evidence) continue;

    ax.log(ax.LogLevelInfo, `[CLD] SQL/database file exposed at ${CLD_PATHS[i]}`);
    scanState.addVuln({
        typeId: 'custom.xml',
        path: CLD_PATHS[i],
        http: job,
        details: `[b]CLD - SQL Dump / Database File Disclosure[/b][break]` +
                 `Path: [code]${CLD_PATHS[i]}[/code][break]` +
                 `Evidence: [code]${ax.util.htmlEncode(evidence)}[/code][break]` +
                 `Size: [code]${body.length} bytes[/code]`
    });
    break;
}
