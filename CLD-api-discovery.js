/****************************************************************
 Name:     CLD - API Discovery
 Author:   CLD
 Severity: medium (spec / GraphQL introspection), low (docs UI / endpoint only)
 Type:     target script (runs once per target)

 Probes the top 25 API documentation locations:
   - OpenAPI / Swagger specs (JSON + YAML)
   - Springfox swagger-resources listing
   - Swagger UI / ReDoc pages
   - GraphQL endpoints (POST introspection query)

 Strict matchers (no keyword guessing):
   spec JSON  : parses as JSON AND has "openapi"/"swagger" AND a "paths" object
   spec YAML  : line-start "openapi: 3" / "swagger: 2" AND line-start "paths:"
   resources  : JSON array whose items have "location" + "swaggerVersion"/"url"
   docs UI    : HTML loading swagger-ui-bundle / SwaggerUIBundle / redoc.standalone
   GraphQL    : JSON with data.__schema.queryType (introspection open), or
                JSON "errors" that mention introspection/__schema (endpoint only)

 One alert per finding type, listing every path where it was found.
 ****************************************************************/

const CLD_SPEC_PATHS = [
    '/swagger.json', '/swagger/v1/swagger.json', '/swagger/doc.json', '/openapi.json',
    '/openapi.yaml', '/swagger.yaml', '/v3/api-docs', '/v2/api-docs', '/api-docs',
    '/api/swagger.json', '/api/openapi.json', '/api/v1/swagger.json', '/api/v1/openapi.json',
    '/api/v2/api-docs', '/api/v3/api-docs'
];
const CLD_RESOURCES_PATHS = ['/swagger-resources'];
const CLD_UI_PATHS = ['/swagger-ui.html', '/swagger-ui/index.html', '/swagger/index.html', '/docs', '/api/docs', '/redoc'];
const CLD_GRAPHQL_PATHS = ['/graphql', '/api/graphql', '/v1/graphql'];
// 15 + 1 + 6 + 3 = 25 requests

const CLD_GQL_QUERY = '{"query":"query CLD { __schema { queryType { name } types { name } } }"}';

function cldRequest(path, method, body) {
    let job = ax.http.job();
    job.hostname = scriptArg.target.host;
    job.port = scriptArg.target.port;
    job.secure = scriptArg.target.secure;
    job.request.uri = path;
    if (method) job.request.method = method;
    if (body) {
        job.request.body = body;
        job.request.addHeader('Content-Type', 'application/json');
        job.request.addHeader('Accept', 'application/json');
    }
    ax.http.execute(job).sync();
    return job;
}

function cldOk(job) {
    return !job.error && job.response && job.response.status === 200 && (job.response.body || '').length > 0;
}

function cldJson(body) {
    try { return JSON.parse(body); } catch (e) { return null; }
}

// --- matchers -------------------------------------------------
function cldMatchSpec(body) {
    let j = cldJson(body);
    if (j && typeof j === 'object' && !Array.isArray(j) &&
        (typeof j.openapi === 'string' || typeof j.swagger === 'string') &&
        j.paths && typeof j.paths === 'object') {
        let eps = Object.keys(j.paths);
        let ver = j.openapi ? 'OpenAPI ' + j.openapi : 'Swagger ' + j.swagger;
        let title = (j.info && j.info.title) ? j.info.title : '';
        return { ver: ver, title: title, count: eps.length, sample: eps.slice(0, 15) };
    }
    if (/^\s*openapi:\s*["']?3\.\d/m.test(body) || /^\s*swagger:\s*["']?2\.0/m.test(body)) {
        if (/^paths:\s*$/m.test(body)) {
            let eps = [];
            let re = /^  (\/[^\s:]*):\s*$/gm, m;
            while ((m = re.exec(body)) !== null) eps.push(m[1]);
            let vm = body.match(/^\s*(openapi|swagger):\s*["']?([\d.]+)/m);
            return { ver: (vm[1] === 'openapi' ? 'OpenAPI ' : 'Swagger ') + vm[2] + ' (YAML)', title: '', count: eps.length, sample: eps.slice(0, 15) };
        }
    }
    return null;
}

function cldMatchResources(body) {
    let j = cldJson(body);
    if (!Array.isArray(j) || j.length === 0) return null;
    let ok = j.filter(x => x && typeof x === 'object' && typeof x.location === 'string' &&
                           (typeof x.swaggerVersion === 'string' || typeof x.url === 'string'));
    return ok.length ? ok.map(x => x.location) : null;
}

function cldMatchUi(body) {
    if (/swagger-ui-bundle(\.min)?\.js|SwaggerUIBundle\s*\(/.test(body)) return 'Swagger UI';
    if (/redoc\.standalone(\.min)?\.js|<redoc[\s>]/i.test(body)) return 'ReDoc';
    return null;
}

function cldMatchGraphql(body) {
    let j = cldJson(body);
    if (!j || typeof j !== 'object') return null;
    if (j.data && j.data.__schema && j.data.__schema.queryType) {
        let types = Array.isArray(j.data.__schema.types) ? j.data.__schema.types.map(t => t.name).filter(n => n && n.indexOf('__') !== 0) : [];
        return { open: true, queryType: j.data.__schema.queryType.name, types: types };
    }
    if (Array.isArray(j.errors) && j.errors.some(e => e && /introspection|__schema/i.test(String(e.message)))) {
        return { open: false };
    }
    return null;
}

// --- run ------------------------------------------------------
let cldFound = { spec: [], resources: [], ui: [], gqlOpen: [], gqlClosed: [] };

CLD_SPEC_PATHS.forEach(p => {
    let job = cldRequest(p);
    if (!cldOk(job)) return;
    let m = cldMatchSpec(job.response.body);
    if (m) cldFound.spec.push({ path: p, job: job, m: m });
});

CLD_RESOURCES_PATHS.forEach(p => {
    let job = cldRequest(p);
    if (!cldOk(job)) return;
    let m = cldMatchResources(job.response.body);
    if (m) cldFound.resources.push({ path: p, job: job, m: m });
});

CLD_UI_PATHS.forEach(p => {
    let job = cldRequest(p);
    if (!cldOk(job)) return;
    let m = cldMatchUi(job.response.body);
    if (m) cldFound.ui.push({ path: p, job: job, m: m });
});

CLD_GRAPHQL_PATHS.forEach(p => {
    let job = cldRequest(p, 'POST', CLD_GQL_QUERY);
    if (job.error || !job.response) return;
    let m = cldMatchGraphql(job.response.body || '');
    if (!m) return;
    (m.open ? cldFound.gqlOpen : cldFound.gqlClosed).push({ path: p, job: job, m: m });
});

// --- report ---------------------------------------------------
function cldList(items) {
    return '[ul]' + items.map(x => `[li][code]${ax.util.htmlEncode(x)}[/code][/li]`).join('') + '[/ul]';
}

function cldReport(hits, title, describe) {
    if (!hits.length) return;
    ax.log(ax.LogLevelInfo, `[CLD] ${title}: ${hits.map(h => h.path).join(', ')}`);
    scanState.addVuln({
        typeId: 'custom.xml',
        path: hits[0].path,
        http: hits[0].job,
        details: `[b]CLD - ${title}[/b][break]Found at:` + cldList(hits.map(h => h.path)) + describe(hits[0])
    });
}

cldReport(cldFound.spec, 'API Discovery: OpenAPI/Swagger Specification Exposed', h =>
    `Version: [code]${ax.util.htmlEncode(h.m.ver)}[/code][break]` +
    (h.m.title ? `Title: [code]${ax.util.htmlEncode(h.m.title)}[/code][break]` : '') +
    `Endpoints in spec: [b]${h.m.count}[/b]` + (h.m.sample.length ? cldList(h.m.sample) : ''));

cldReport(cldFound.resources, 'API Discovery: Swagger Resources Listing Exposed', h =>
    'Listed API specs:' + cldList(h.m));

cldReport(cldFound.gqlOpen, 'API Discovery: GraphQL Introspection Enabled', h =>
    `Query type: [code]${ax.util.htmlEncode(h.m.queryType)}[/code][break]` +
    `Schema types: [b]${h.m.types.length}[/b]` + (h.m.types.length ? cldList(h.m.types.slice(0, 15)) : ''));

cldReport(cldFound.gqlClosed, 'API Discovery: GraphQL Endpoint Found (introspection disabled)', h =>
    'The endpoint answered as GraphQL but rejected introspection.');

cldReport(cldFound.ui, 'API Discovery: API Documentation UI Exposed', h =>
    `UI type: [code]${h.m}[/code]`);
