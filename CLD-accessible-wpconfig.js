/****************************************************************
 Name:     CLD - WordPress Accessible wp-config
 Author:   CLD
 Severity: high
 Type:     target script (runs once per target)

 Probes 100 common wp-config backup/copy locations.
 A hit needs HTTP 200 and real WordPress config content
 (DB_NAME / DB_USER / DB_PASSWORD / AUTH_KEY / WPENGINE_ACCOUNT).
 Stops at the first match.
 ****************************************************************/

const CLD_PATHS = [
    '/wp-config.php', '/wp-config.sample.php', '/wp-config-sample.php', '/wp-config.php.bak',
    '/wp-config.php.back', '/wp-config.php.backup', '/wp-config.php.old', '/wp-config.php.orig',
    '/wp-config.php.original', '/wp-config.php.save', '/wp-config.php.copy', '/wp-config.php.tmp',
    '/wp-config.php.temp', '/wp-config.php.new', '/wp-config.php.dist', '/wp-config.php.1',
    '/wp-config.old.php', '/wp-config.new.php', '/wp-config.bak', '/wp-config.old',
    '/wp-config.txt', '/wp-config.ini', '/wp-config.inc', '/wp-config.php.txt',
    '/wp-config.php.html', '/wp-config.php.inc', '/wp-config.php_bak', '/wp-config.php-bak',
    '/wp-config_bak.php', '/wp-config-backup.php', '/wp-config-backup.txt', '/wp-config.php~',
    '/wp-config.php.bak1', '/wp-config.php.bak2', '/wp-config.php.bak3', '/wp-config.php.old1',
    '/wp-config.php.old2', '/wp-config.php.2', '/wp-config.php.3', '/wp-config1.php',
    '/wp-config2.php', '/wp-config-1.php', '/wp-config-2.php', '/wp-config_1.php',
    '/wp-config_2.php', '/wp-config (1).php', '/wp-config (2).php', '/wp-config-copy.php',
    '/wp-config-copy(1).php', '/wp-config.php.2024', '/wp-config.php.2025', '/wp-config.2024.php',
    '/wp-config.2025.php', '/wp-config-2024-01-01.php', '/wp-config_backup_2024.php', '/.wp-config.php.swp',
    '/.wp-config.php.swo', '/.wp-config.php.swn', '/wp-config.php.swp', '/wp-config.php.swo',
    '/wp-config.php.swn', '/.#wp-config.php', '/#wp-config.php#', '/wp-config.php.rej',
    '/wp-config.php.merge', '/_wpeprivate/config.json', '/wp-config-local.php', '/wp-config-dev.php',
    '/wp-config-development.php', '/wp-config-staging.php', '/wp-config-production.php', '/wp-config-prod.php',
    '/wp-config-test.php', '/wp-config-live.php', '/backup/wp-config.php', '/backups/wp-config.php',
    '/old/wp-config.php', '/wp-content/wp-config.php', '/wp-content/uploads/wp-config.php', '/wp-admin/wp-config.php',
    '/config/wp-config.php', '/_backup/wp-config.php', '/tmp/wp-config.php', '/wp-config.yml',
    '/wp-config.yaml', '/wp-config.json', '/wp-config.env', '/.env.wp-config',
    '/wp-config.php.php', '/wp-config.php.bak.php', '/wp-config.php.old.bak', '/WP-CONFIG.PHP',
    '/Wp-Config.php.bak', '/wp-config.php.sav', '/wp-config.php.bk', '/wp-config.php.dev',
    '/wp-config.php.prod', '/wp-config.php.local', '/wp-config.php.bak.old', '/wp-config.php.orig.bak'
];

// Real config syntax only - a page that merely mentions "DB_PASSWORD" must not match.
//   PHP:      define( 'DB_PASSWORD', '...' );
//   env/yaml: DB_PASSWORD=... / DB_PASSWORD: ...
//   json:     "DB_PASSWORD": ...
// Needs >= 2 distinct settings, or a WP Engine account assignment.
const CLD_KEYS = 'DB_NAME|DB_USER|DB_PASSWORD|DB_HOST|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY';
const CLD_PHP_RE = new RegExp(`define\\s*\\(\\s*['"](${CLD_KEYS})['"]\\s*,`, 'g');
const CLD_KV_RE  = new RegExp(`^\\s*["']?(${CLD_KEYS})["']?\\s*[:=]`, 'gm');
const CLD_WPE_RE = /["']?WPENGINE_ACCOUNT["']?\s*[:=,]\s*["'][^"']+["']/;

function cldFindMarkers(body) {
    let found = {};
    [CLD_PHP_RE, CLD_KV_RE].forEach(re => {
        re.lastIndex = 0;
        let m;
        while ((m = re.exec(body)) !== null) found[m[1]] = true;
    });
    if (CLD_WPE_RE.test(body)) found['WPENGINE_ACCOUNT'] = true;
    let keys = Object.keys(found);
    return (keys.length >= 2 || found['WPENGINE_ACCOUNT']) ? keys : [];
}

function cldProbe(path) {
    let job = ax.http.job();
    job.hostname = scriptArg.target.host;
    job.port = scriptArg.target.port;
    job.secure = scriptArg.target.secure;
    job.request.uri = path.replace(/ /g, '%20').replace(/#/g, '%23');
    ax.http.execute(job).sync();
    return job;
}

for (let i = 0; i < CLD_PATHS.length; i++) {
    let job = cldProbe(CLD_PATHS[i]);
    if (job.error || job.response.status !== 200) continue;

    let body = job.response.body || '';
    let found = cldFindMarkers(body);
    if (found.length === 0) continue;

    ax.log(ax.LogLevelInfo, `[CLD] wp-config exposed at ${CLD_PATHS[i]}`);
    scanState.addVuln({
        typeId: 'custom.xml',
        path: CLD_PATHS[i],
        http: job,
        details: `[b]CLD - WordPress Accessible wp-config[/b][break]` +
                 `Path: [code]${CLD_PATHS[i]}[/code][break]` +
                 `Markers found: [code]${found.join(', ')}[/code]`
    });
    break;
}
