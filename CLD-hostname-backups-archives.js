/****************************************************************
 Name:     CLD - Backup Archive Disclosure
 Author:   CLD
 Severity: critical
 Type:     target script (runs once per target)

 Looks for exposed site backup archives. Max 100 requests,
 most likely names first:
   1. generic names in web root   /backup.zip /site.zip /www.zip /html.zip ...
   2. names built from the host    /www.example.com.zip /example.com.zip /example.zip
   3. other formats                .tar.gz .tgz .rar .7z
   4. backup dirs                  /backup/ /backups/

 A hit needs HTTP 200, a non-HTML response, body > 64 bytes AND a
 real archive signature (ZIP, gzip/tar.gz, RAR, 7z, bzip2, plain tar).
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
        let sld = (p.length >= 3 && p[p.length - 1].length === 2 && p[p.length - 2].length <= 3) ? p[p.length - 3] : p[p.length - 2];
        out.push(sld);
    }
    return out.filter((v, i) => v && out.indexOf(v) === i);
}

const CLD_HOSTS = cldHostVariants(scriptArg.target.host);

const CLD_GENERIC = ['backup', 'site', 'www', 'html', 'public_html', 'htdocs', 'web', 'website',
                     'files', 'data', 'db', 'archive', 'old', 'wordpress', 'wp', 'src',
                     'source', 'app', 'full', 'latest', 'release', 'backup_site', 'site_backup', 'www_backup'];

function cldBuildPaths() {
    let list = [];
    let add = p => { if (list.indexOf(p) === -1) list.push(p); };

    // 1. generic .zip in web root (most common)
    CLD_GENERIC.forEach(n => add(`/${n}.zip`));
    // 2. host-based .zip / .tar.gz
    CLD_HOSTS.forEach(h => ['', '_backup', '-backup', '_full', '_site'].forEach(s => add(`/${h}${s}.zip`)));
    CLD_HOSTS.forEach(h => ['', '_backup'].forEach(s => add(`/${h}${s}.tar.gz`)));
    // 3. generic .tar.gz for the top names
    CLD_GENERIC.slice(0, 14).forEach(n => add(`/${n}.tar.gz`));
    // 4. backup dirs
    ['/backup/', '/backups/'].forEach(d => ['backup', 'site', 'www', 'full', 'html', 'db'].forEach(n => add(`${d}${n}.zip`)));
    CLD_HOSTS.forEach(h => { add(`/backup/${h}.zip`); add(`/backups/${h}.zip`); });
    // 5. other formats for the top names
    ['backup', 'site', 'www', 'html', 'public_html', 'htdocs', 'web', 'website'].forEach(n => {
        add(`/${n}.tgz`); add(`/${n}.rar`); add(`/${n}.7z`);
    });
    CLD_HOSTS.forEach(h => { add(`/${h}.tgz`); add(`/${h}.rar`); add(`/${h}.7z`); });
    ['backup', 'site', 'www'].forEach(n => { add(`/${n}.tar`); add(`/${n}.tar.bz2`); });

    return list.slice(0, CLD_MAX);
}

const CLD_PATHS = cldBuildPaths();

function cldByte(body, i, code) {
    let c = body.charCodeAt(i);
    return c === code || c === 0xFFFD;   // non-ASCII bytes may arrive as U+FFFD
}

function cldArchiveType(body) {
    if (body.length < 6) return null;
    if (body.startsWith('PK\x03\x04')) return 'ZIP';
    if (body.startsWith('Rar!\x1a\x07')) return 'RAR';
    if (body.charCodeAt(0) === 0x1f && cldByte(body, 1, 0x8b)) return 'gzip / tar.gz';
    if (body.startsWith('7z') && cldByte(body, 2, 0xbc) && cldByte(body, 3, 0xaf)) return '7z';
    if (body.startsWith('BZh') && /[1-9]/.test(body.charAt(3))) return 'bzip2';
    if (body.length > 262 && body.substr(257, 5) === 'ustar') return 'tar';
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

    let kind = cldArchiveType(body);
    if (!kind) continue;

    ax.log(ax.LogLevelInfo, `[CLD] ${kind} backup archive exposed at ${CLD_PATHS[i]}`);
    scanState.addVuln({
        typeId: 'custom.xml',
        path: CLD_PATHS[i],
        http: job,
        details: `[b]CLD - Backup Archive Disclosure[/b][break]` +
                 `Path: [code]${CLD_PATHS[i]}[/code][break]` +
                 `Archive type: [code]${kind}[/code][break]` +
                 `Content-Type: [code]${ctype}[/code][break]` +
                 `Size: [code]${body.length} bytes[/code]`
    });
    break;
}
