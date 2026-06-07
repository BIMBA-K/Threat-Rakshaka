// Session Protection
if (!localStorage.getItem('policeUser')) {
    window.location.href = 'login.html';
}

// Theme Management
const themeToggle = document.getElementById('theme-toggle');
const body = document.body;

const currentTheme = localStorage.getItem('theme');
if (currentTheme === 'light') {
    body.classList.add('light-mode');
}

if (themeToggle) {
    themeToggle.addEventListener('click', () => {
        body.classList.toggle('light-mode');
        const theme = body.classList.contains('light-mode') ? 'light' : 'dark';
        localStorage.setItem('theme', theme);
    });
}

const SUPABASE_URL = 'https://npfvvegmxgkkhyxkephc.supabase.co';
const SUPABASE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im5wZnZ2ZWdteGdra2h5eGtlcGhjIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzczODQzNzQsImV4cCI6MjA5Mjk2MDM3NH0.S4wKfp_5b_KJKyt4_yobbPZY6VVdyoaIHmGJXQs2FgU';

const statTotal = document.getElementById('stat-total');
const statDangerous = document.getElementById('stat-dangerous');
const statSuspicious = document.getElementById('stat-suspicious');
const statRepeat = document.getElementById('stat-repeat');
const lastUpdated = document.getElementById('last-updated');
const searchInput = document.getElementById('search-input');
const sortSelect = document.getElementById('sort-select');
const tableBody = document.getElementById('table-body');

// Phase 3 Elements
const statRoots = document.getElementById('stat-roots');
const statClusters = document.getElementById('stat-clusters');
const statActiveHash = document.getElementById('stat-active-hash');
const statDangerCluster = document.getElementById('stat-danger-cluster');
const rapidSpreadAlert = document.getElementById('rapid-spread-alert');
const rootTableBody = document.getElementById('root-table-body');
const clusterContainer = document.getElementById('cluster-container');

// Phase 4 Elements
const statDomains = document.getElementById('stat-domains');
const statIps = document.getElementById('stat-ips');
const statCerts = document.getElementById('stat-certs');
const statTopDomain = document.getElementById('stat-top-domain');
const statTopIp = document.getElementById('stat-top-ip');
const btnExport = document.getElementById('btn-export');
const graphFocusSelect = document.getElementById('graph-focus-select');

// Awareness Generator Elements
const apkAlertSelect = document.getElementById('apk-alert-select');
const advisoryEditor = document.getElementById('advisory-editor');
const charCounter = document.getElementById('char-counter');
const draftStatus = document.getElementById('draft-status');
const btnGenerateTemplate = document.getElementById('btn-generate-template');
const btnPublishAdvisory = document.getElementById('btn-publish-advisory');
const unifiedPostBody = document.getElementById('unified-post-body');
const btnCopyPost = document.getElementById('btn-copy-post');
const btnDownloadPoster = document.getElementById('btn-download-poster');
const awarenessHistoryList = document.getElementById('awareness-history-list');
const posterCanvas = document.getElementById('poster-canvas');
const statBlacklistCount = document.getElementById('stat-blacklist-count');

let blacklistedHashes = new Set();
let dismissedThreatIds = new Set(JSON.parse(localStorage.getItem('dismissedThreats') || '[]'));

let timelineChart = null;
let selectedGraphId = 'all';

// Graph State
let network = null;
let nodes = new vis.DataSet();
let edges = new vis.DataSet();

// State
let threatData = [];
let filteredData = [];

// Phase 4 Deterministic Random Generator
function seededRandom(seedStr) {
    let hash = 0;
    for (let i = 0; i < seedStr.length; i++) {
        hash = Math.imul(31, hash) + seedStr.charCodeAt(i) | 0;
    }
    return function() {
        hash = Math.imul(hash, 1664525) + 1013904223 | 0;
        return (hash >>> 0) / 4294967296;
    };
}

const MALICIOUS_URL_TEMPLATES = [
    "http://malicious-login.example.com/auth",
    "http://update-secure-bank.example.net/v2",
    "https://auth-verification-required.xyz/login",
    "http://free-loan-approval.biz/apply",
    "http://device-cleaner-pro.info/scan",
    "https://secure-account-recovery.com/reset",
    "http://sms-gateway-api.net/send"
];

function generateIntelligence(apkHash) {
    if (!apkHash) return null;
    
    const rng = seededRandom(apkHash);
    
    // Generate 1-3 URLs
    const numUrls = Math.floor(rng() * 3) + 1;
    const urls = new Set();
    while(urls.size < numUrls) {
        urls.add(MALICIOUS_URL_TEMPLATES[Math.floor(rng() * MALICIOUS_URL_TEMPLATES.length)]);
    }
    
    const urlArray = Array.from(urls);
    const domains = [...new Set(urlArray.map(u => {
        try { return new URL(u).hostname; } catch(e) { return u.split('/')[2] || u; }
    }))];
    
    // Generate 1-2 IPs
    const numIps = Math.floor(rng() * 2) + 1;
    const ips = [];
    for(let i=0; i<numIps; i++) {
        ips.push(`${Math.floor(rng()*255)}.${Math.floor(rng()*255)}.${Math.floor(rng()*255)}.${Math.floor(rng()*255)}`);
    }
    
    // Generate Cert
    const certHex = apkHash.substring(0, 8).toUpperCase();
    const certId = `CERT-${certHex}`;
    
    return { urls: urlArray, domains: domains, ips: ips, cert: certId };
}

// Fetch data from Supabase
async function fetchThreatReports() {
    try {
        const response = await fetch(`${SUPABASE_URL}/rest/v1/threat_reports?select=*`, {
            headers: {
                'apikey': SUPABASE_KEY,
                'Authorization': `Bearer ${SUPABASE_KEY}`
            }
        });
        
        if (!response.ok) throw new Error('Network response was not ok');
        
        const data = await response.json();
        
        const filteredNewData = data.filter(r => !dismissedThreatIds.has(r.id));
        
        // Only update if data has changed to prevent unnecessary re-renders
        if (JSON.stringify(filteredNewData) !== JSON.stringify(threatData.map(r => {
            const { intel, ...rest } = r; return rest;
        }))) {
            threatData = filteredNewData.map(r => {
                r.intel = generateIntelligence(r.apk_hash);
                return r;
            });
            processAndRenderData();
        }
        
        updateTimestamp();
    } catch (error) {
        console.error('Error fetching data:', error);
    }
}

// Process data, calculate stats, filter, sort, and render
function processAndRenderData() {
    calculateStats();
    analyzeThreats();
    updateGraphFocusOptions();
    updateAwarenessApkSelect();
    applyFiltersAndSort();
    renderTable();
    updateGraphData();
}

// Update the options in the Awareness APK Select (DANGEROUS only)
function updateAwarenessApkSelect() {
    if (!apkAlertSelect) return;
    
    const currentValue = apkAlertSelect.value;
    apkAlertSelect.innerHTML = '<option value="">-- Select a Threat --</option>';
    
    const dangerousApks = threatData.filter(r => (r.risk_level || '').toUpperCase() === 'DANGEROUS');
    
    dangerousApks.forEach(report => {
        const option = document.createElement('option');
        option.value = report.id;
        option.textContent = `${report.app_name || 'Unknown'} (Score: ${report.risk_score})`;
        apkAlertSelect.appendChild(option);
    });
    
    if (currentValue && [...apkAlertSelect.options].some(opt => opt.value === currentValue)) {
        apkAlertSelect.value = currentValue;
    }
}

// Update the options in the Graph Focus dropdown
function updateGraphFocusOptions() {
    if (!graphFocusSelect) return;
    
    const currentValue = graphFocusSelect.value;
    graphFocusSelect.innerHTML = '<option value="all">Global Intelligence Overview (Full Network)</option>';
    
    // Sort threats by name for easy finding
    const sortedThreats = [...threatData].sort((a, b) => (a.app_name || '').localeCompare(b.app_name || ''));
    
    sortedThreats.forEach(report => {
        const option = document.createElement('option');
        option.value = report.id;
        option.textContent = `${report.app_name || 'Unknown'} [${(report.apk_hash || '').substring(0, 8)}]`;
        graphFocusSelect.appendChild(option);
    });
    
    // Restore value if it still exists
    if ([...graphFocusSelect.options].some(opt => opt.value === currentValue)) {
        graphFocusSelect.value = currentValue;
    } else {
        graphFocusSelect.value = 'all';
        selectedGraphId = 'all';
    }
}

// Analyze Threats (Phase 3)
function analyzeThreats() {
    if (!threatData || threatData.length === 0) return;
    
    // 1. Calculate Hashes and Occurrences
    const hashData = {};
    threatData.forEach(r => {
        if (!r.apk_hash) return;
        if (!hashData[r.apk_hash]) {
            hashData[r.apk_hash] = {
                hash: r.apk_hash,
                count: 0,
                scores: [],
                first_seen: new Date(r.detected_time),
                last_seen: new Date(r.detected_time),
                apps: new Set()
            };
        }
        
        const hd = hashData[r.apk_hash];
        hd.count++;
        hd.scores.push(r.risk_score || 0);
        hd.apps.add(r.app_name);
        
        const dt = new Date(r.detected_time);
        if (dt < hd.first_seen) hd.first_seen = dt;
        if (dt > hd.last_seen) hd.last_seen = dt;
    });

    // 2. Root Sources Detection (> 5 occurrences)
    const rootSources = Object.values(hashData).filter(h => h.count > 5).sort((a, b) => b.count - a.count);
    
    const mostActive = Object.values(hashData).sort((a, b) => b.count - a.count)[0];
    const mostActiveHashText = mostActive ? `${mostActive.hash.substring(0,8)}... (${mostActive.count})` : '--';
    
    // Render Root Table
    if (rootTableBody) {
        if (rootSources.length === 0) {
            rootTableBody.innerHTML = `<tr><td colspan="5" class="text-center">No root sources detected yet.</td></tr>`;
        } else {
            rootTableBody.innerHTML = '';
            rootSources.forEach(root => {
                const avgScore = Math.round(root.scores.reduce((a,b) => a+b, 0) / root.scores.length);
                const tr = document.createElement('tr');
                tr.className = 'root-row';
                tr.innerHTML = `
                    <td class="hash-text font-medium" style="color: #b91c1c;">${escapeHTML(root.hash)}</td>
                    <td><strong>${root.count}</strong></td>
                    <td>${avgScore}/100</td>
                    <td>${root.first_seen.toLocaleString()}</td>
                    <td>${root.last_seen.toLocaleString()}</td>
                `;
                rootTableBody.appendChild(tr);
            });
        }
    }
    
    // 3. Cluster Detection (Union Find)
    const parent = {};
    const getParent = (i) => {
        if (parent[i] === undefined) parent[i] = i;
        if (parent[i] !== i) parent[i] = getParent(parent[i]);
        return parent[i];
    };
    const union = (i, j) => {
        parent[getParent(i)] = getParent(j);
    };
    
    const hashToApks = {};
    const permToApks = {};
    
    threatData.forEach((r, idx) => {
        if (r.apk_hash) {
            if (!hashToApks[r.apk_hash]) hashToApks[r.apk_hash] = [];
            hashToApks[r.apk_hash].push(idx);
        }
        if (r.permissions) {
            const permPattern = r.permissions.split(',').map(s=>s.trim()).sort().join('|');
            if (permPattern) {
                if (!permToApks[permPattern]) permToApks[permPattern] = [];
                permToApks[permPattern].push(idx);
            }
        }
    });
    
    Object.values(hashToApks).forEach(group => {
        for(let i=1; i<group.length; i++) union(group[0], group[i]);
    });
    Object.values(permToApks).forEach(group => {
        for(let i=1; i<group.length; i++) union(group[0], group[i]);
    });
    
    const clusterMap = {};
    threatData.forEach((r, idx) => {
        const root = getParent(idx);
        if (!clusterMap[root]) clusterMap[root] = [];
        clusterMap[root].push(r);
    });
    
    const clusters = Object.values(clusterMap).filter(c => c.length > 1).sort((a,b) => b.length - a.length);
    
    const clusteredApkIds = new Set();
    clusters.forEach(c => c.forEach(r => clusteredApkIds.add(r.id)));
    window.clusteredApkIds = clusteredApkIds;
    window.rootHashStrings = new Set(rootSources.map(r => r.hash));

    // Render Clusters
    let mostDangerousClusterScore = 0;
    let mostDangerousClusterId = '--';
    
    if (clusterContainer) {
        if (clusters.length === 0) {
            clusterContainer.innerHTML = `<div class="empty-state text-center" style="width: 100%;">No behavioral clusters detected.</div>`;
        } else {
            clusterContainer.innerHTML = '';
            clusters.forEach((c, idx) => {
                const clusterId = `CLS-${String(idx + 1).padStart(3, '0')}`;
                const permCounts = {};
                let avgScore = 0;
                const riskCounts = {};
                
                c.forEach(r => {
                    avgScore += (r.risk_score || 0);
                    const rLevel = (r.risk_level || 'UNKNOWN').toUpperCase();
                    riskCounts[rLevel] = (riskCounts[rLevel] || 0) + 1;
                    
                    if (r.permissions) {
                        r.permissions.split(',').forEach(p => {
                            const pt = p.trim();
                            if (pt) permCounts[pt] = (permCounts[pt] || 0) + 1;
                        });
                    }
                });
                
                avgScore = Math.round(avgScore / c.length);
                if (avgScore > mostDangerousClusterScore) {
                    mostDangerousClusterScore = avgScore;
                    mostDangerousClusterId = clusterId;
                }
                
                let commonPerm = 'None';
                let highestPermCount = 0;
                for(const p in permCounts) {
                    if (permCounts[p] > highestPermCount) {
                        highestPermCount = permCounts[p];
                        commonPerm = p;
                    }
                }
                
                let mostFreqRisk = 'UNKNOWN';
                let highestRiskCount = 0;
                for(const r in riskCounts) {
                    if (riskCounts[r] > highestRiskCount) {
                        highestRiskCount = riskCounts[r];
                        mostFreqRisk = r;
                    }
                }
                
                const card = document.createElement('div');
                card.className = 'cluster-card';
                card.innerHTML = `
                    <div class="cluster-header">
                        <span class="cluster-id">${clusterId}</span>
                        <span class="cluster-count">${c.length} APKs</span>
                    </div>
                    <div class="cluster-body">
                        <div class="detail-row">
                            <div class="detail-label">Most Common Permission</div>
                            <div class="detail-value text-secondary" style="font-size: 0.8rem;">${escapeHTML(commonPerm.substring(0,40))}</div>
                        </div>
                        <div class="detail-row">
                            <div class="detail-label">Avg Risk Score</div>
                            <div class="detail-value"><strong>${avgScore}</strong>/100</div>
                        </div>
                        <div class="detail-row">
                            <div class="detail-label">Prevalent Risk Level</div>
                            <div class="detail-value"><strong>${escapeHTML(mostFreqRisk)}</strong></div>
                        </div>
                    </div>
                `;
                clusterContainer.appendChild(card);
            });
        }
    } else {
        // Still need to find most dangerous cluster for stat card
        clusters.forEach((c, idx) => {
            const clusterId = `CLS-${String(idx + 1).padStart(3, '0')}`;
            let avgScore = 0;
            c.forEach(r => { avgScore += (r.risk_score || 0); });
            avgScore = Math.round(avgScore / c.length);
            if (avgScore > mostDangerousClusterScore) {
                mostDangerousClusterScore = avgScore;
                mostDangerousClusterId = clusterId;
            }
        });
    }

    // 4. Rapid Spread Detection
    let rapidSpread = false;
    Object.values(hashData).forEach(hd => {
        const diffHrs = (hd.last_seen - hd.first_seen) / (1000 * 60 * 60);
        if (hd.count >= 5 && diffHrs <= 24 && diffHrs >= 0) {
             rapidSpread = true;
        }
    });
    
    if (rapidSpreadAlert) {
        if (rapidSpread) {
            rapidSpreadAlert.style.display = 'flex';
        } else {
            rapidSpreadAlert.style.display = 'none';
        }
    }

    // Phase 4 Intel Stats
    const allDomains = {};
    const allIps = {};
    const allCerts = new Set();
    
    threatData.forEach(r => {
        if (!r.intel) return;
        r.intel.domains.forEach(d => { allDomains[d] = (allDomains[d] || 0) + 1; });
        r.intel.ips.forEach(ip => { allIps[ip] = (allIps[ip] || 0) + 1; });
        allCerts.add(r.intel.cert);
    });
    
    let topDomain = '--', topDomainCount = 0;
    for(const d in allDomains) {
        if(allDomains[d] > topDomainCount) { topDomainCount = allDomains[d]; topDomain = d; }
    }
    
    let topIp = '--', topIpCount = 0;
    for(const ip in allIps) {
        if(allIps[ip] > topIpCount) { topIpCount = allIps[ip]; topIp = ip; }
    }
    
    window.domainCounts = allDomains; // For graph sharing check
    window.ipCounts = allIps; // For IP sharing check
    
    if (statDomains) {
        animateValue(statDomains, parseInt(statDomains.innerText) || 0, Object.keys(allDomains).length, 500);
        animateValue(statIps, parseInt(statIps.innerText) || 0, Object.keys(allIps).length, 500);
        animateValue(statCerts, parseInt(statCerts.innerText) || 0, allCerts.size, 500);
        statTopDomain.innerText = topDomainCount > 1 ? `${topDomain} (${topDomainCount})` : topDomain;
        statTopIp.innerText = topIpCount > 1 ? `${topIp} (${topIpCount})` : topIp;
    }

    // Timeline Chart
    updateTimeline();

    // 5. Update Stats
    if (statRoots) animateValue(statRoots, parseInt(statRoots.innerText) || 0, rootSources.length, 500);
    if (statClusters) animateValue(statClusters, parseInt(statClusters.innerText) || 0, clusters.length, 500);
    if (statActiveHash) statActiveHash.innerText = mostActiveHashText;
    if (statDangerCluster) statDangerCluster.innerText = clusters.length > 0 ? `${mostDangerousClusterId} (${mostDangerousClusterScore})` : '--';
}

// Calculate Statistics
function calculateStats() {
    if (!threatData || threatData.length === 0) return;

    const total = threatData.length;
    let dangerous = 0;
    let suspicious = 0;
    const hashCounts = {};
    let repeatCount = 0;

    threatData.forEach(report => {
        if (report.risk_level && report.risk_level.toUpperCase() === 'DANGEROUS') {
            dangerous++;
        } else if (report.risk_level && report.risk_level.toUpperCase() === 'SUSPICIOUS') {
            suspicious++;
        }
        if (report.apk_hash) {
            hashCounts[report.apk_hash] = (hashCounts[report.apk_hash] || 0) + 1;
        }
    });

    for (const hash in hashCounts) {
        if (hashCounts[hash] > 1) {
            repeatCount++;
        }
    }

    if (statTotal) animateValue(statTotal, parseInt(statTotal.innerText) || 0, total, 500);
    if (statDangerous) animateValue(statDangerous, parseInt(statDangerous.innerText) || 0, dangerous, 500);
    if (statSuspicious) animateValue(statSuspicious, parseInt(statSuspicious.innerText) || 0, suspicious, 500);
    if (statRepeat) animateValue(statRepeat, parseInt(statRepeat.innerText) || 0, repeatCount, 500);
}

// Apply Search Filter and Sort Logic
function applyFiltersAndSort() {
    const searchTerm = (searchInput ? searchInput.value : '').toLowerCase();
    const sortOption = sortSelect ? sortSelect.value : 'time-desc';

    filteredData = threatData.filter(report => {
        const appName = (report.app_name || '').toLowerCase();
        const riskLevel = (report.risk_level || '').toLowerCase();
        const hash = (report.apk_hash || '').toLowerCase();
        let intelStr = '';
        if (report.intel) {
            intelStr = report.intel.domains.join(' ').toLowerCase() + ' ' + 
                       report.intel.ips.join(' ').toLowerCase() + ' ' + 
                       report.intel.cert.toLowerCase();
        }
        return appName.includes(searchTerm) || 
               riskLevel.includes(searchTerm) || 
               hash.includes(searchTerm) ||
               intelStr.includes(searchTerm);
    });

    filteredData.sort((a, b) => {
        switch (sortOption) {
            case 'time-desc': return new Date(b.detected_time) - new Date(a.detected_time);
            case 'time-asc': return new Date(a.detected_time) - new Date(b.detected_time);
            case 'score-desc': return (b.risk_score || 0) - (a.risk_score || 0);
            case 'score-asc': return (a.risk_score || 0) - (b.risk_score || 0);
            default: return 0;
        }
    });
}

// Render Table Rows
function renderTable() {
    if (!tableBody) return;
    if (filteredData.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="6" class="text-center">No matching threat reports found.</td></tr>';
        return;
    }
    tableBody.innerHTML = '';
    filteredData.forEach(report => {
        const tr = document.createElement('tr');
        const riskLevel = (report.risk_level || '').toUpperCase();
        if (riskLevel === 'DANGEROUS') tr.classList.add('row-dangerous');
        else if (riskLevel === 'SUSPICIOUS') tr.classList.add('row-suspicious');
        const detectDate = new Date(report.detected_time);
        const formattedDate = !isNaN(detectDate.getTime()) ? detectDate.toLocaleString() : 'Unknown Time';
        let badgeClass = 'badge-safe';
        if (riskLevel === 'DANGEROUS') badgeClass = 'badge-dangerous';
        if (riskLevel === 'SUSPICIOUS') badgeClass = 'badge-suspicious';
        const isBlacklisted = blacklistedHashes.has(report.apk_hash);
        tr.innerHTML = `
            <td class="font-medium">${escapeHTML(report.app_name || 'Unknown')}</td>
            <td><strong>${report.risk_score || 0}</strong>/100</td>
            <td><span class="badge ${badgeClass}">${escapeHTML(riskLevel)}</span></td>
            <td><span class="hash-text">${escapeHTML(report.apk_hash || 'N/A')}</span></td>
            <td>${escapeHTML(report.permissions || 'None specified')}</td>
            <td>${formattedDate}</td>
            <td>
                <div style="display: flex; gap: 0.5rem; align-items: center;">
                    <button class="btn-sm blacklist-btn" 
                        ${isBlacklisted ? 'disabled' : ''} 
                        style="background: ${isBlacklisted ? '#1e293b' : '#ef4444'}; color: white; border: none; border-radius: 4px; padding: 0.4rem 0.8rem; font-size: 0.75rem; cursor: ${isBlacklisted ? 'not-allowed' : 'pointer'};"
                        onclick="blacklistApk(this, '${report.apk_hash}', '${escapeHTML(report.app_name || 'Unknown')}', '${escapeHTML(riskLevel)}')">
                        ${isBlacklisted ? '✔ Blacklisted' : '🚫 Blacklist'}
                    </button>
                    <button class="btn-delete" onclick="deleteThreat('${report.id}')">
                        <i class="fa-solid fa-trash-can"></i> Delete
                    </button>
                </div>
            </td>
        `;
        tableBody.appendChild(tr);
    });
}

function animateValue(obj, start, end, duration) {
    if (start === end) { obj.innerText = end; return; }
    let startTimestamp = null;
    const step = (timestamp) => {
        if (!startTimestamp) startTimestamp = timestamp;
        const progress = Math.min((timestamp - startTimestamp) / duration, 1);
        obj.innerText = Math.floor(progress * (end - start) + start);
        if (progress < 1) window.requestAnimationFrame(step);
    };
    window.requestAnimationFrame(step);
}

function escapeHTML(str) {
    const div = document.createElement('div');
    div.innerText = str;
    return div.innerHTML;
}

function updateTimestamp() {
    if (!lastUpdated) return;
    const now = new Date();
    lastUpdated.innerText = `Last update: ${now.toLocaleTimeString()}`;
}

// Graph Initialization
function initGraph() {
    const container = document.getElementById('network-graph-container');
    if (!container) return;
    const data = { nodes: nodes, edges: edges };
    const options = {
        nodes: {
            shape: 'dot', size: 22,
            font: { size: 13, color: '#f8fafc', face: 'Inter', strokeWidth: 0 },
            borderWidth: 2,
            shadow: { enabled: true, color: 'rgba(0,0,0,0.5)', size: 8, x: 2, y: 2 }
        },
        edges: { 
            width: 1, 
            color: { color: 'rgba(148, 163, 184, 0.3)', highlight: '#22d3ee', hover: '#22d3ee' }, 
            smooth: { type: 'continuous' } 
        },
        physics: {
            solver: 'barnesHut',
            barnesHut: {
                gravitationalConstant: -4000,
                centralGravity: 0.3,
                springLength: 180,
                springConstant: 0.05,
                damping: 0.8,
                avoidOverlap: 1
            },
            maxVelocity: 40,
            timestep: 0.3,
            stabilization: { 
                iterations: 500,
                fit: true
            }
        },
        interaction: { hover: true, tooltipDelay: 200, zoomView: true, dragView: true }
    };
    setTimeout(() => {
        network = new vis.Network(container, data, options);
        
        // Stop physics after stabilization to prevent swirling/unstable movement
        network.on("stabilizationIterationsDone", function () {
            network.setOptions({ physics: { enabled: false } });
        });

        network.on("click", function (params) {
            if (params.nodes.length > 0) {
                const nodeId = params.nodes[0];
                const nodeData = nodes.get(nodeId);
                if (nodeData) displayNodeDetails(nodeData);
            }
        });
    }, 100);
}

// Graph Data Update
function updateGraphData() {
    // If no threat data, generate some mock data for demo as requested
    const workingData = (threatData && threatData.length > 0) ? threatData : generateMockThreatData();
    
    const newNodes = [];
    const newEdges = [];
    const nodeIds = new Set();
    const edgeIds = new Set();
    
    // Determine which reports to show on graph
    let dataToGraph = workingData;
    if (selectedGraphId !== 'all') {
        dataToGraph = workingData.filter(r => r.id === selectedGraphId);
    }
    
    dataToGraph.forEach(report => {
        // 1. APK Hash Node (Central)
        const apkHash = report.apk_hash || 'UNKNOWN_HASH';
        const apkNodeId = `apk_${apkHash}`;
        
        if (!nodeIds.has(apkNodeId)) {
            const shortHash = apkHash.length > 12 ? apkHash.substring(0, 12) + '...' : apkHash;
            newNodes.push({
                id: apkNodeId,
                label: `APK: ${shortHash}`,
                shape: 'box',
                color: { background: '#ef4444', border: '#b91c1c', highlight: { background: '#f87171', border: '#ef4444' } },
                font: { color: '#ffffff' },
                group: 'apk',
                raw_data: report
            });
            nodeIds.add(apkNodeId);
        }

        // Infrastructure Nodes
        const intel = report.intel || { domains: ['mock-malware-cnc.com'], ips: ['192.168.1.100'], cert: 'CERT-MOCK-99' };
        
        // 2. Domain Nodes
        intel.domains.forEach(domain => {
            const domId = `dom_${domain}`;
            if (!nodeIds.has(domId)) {
                newNodes.push({
                    id: domId,
                    label: domain,
                    shape: 'ellipse',
                    color: { background: '#f97316', border: '#c2410c', highlight: { background: '#fb923c', border: '#f97316' } },
                    font: { color: '#ffffff' },
                    group: 'domain',
                    details: { name: domain }
                });
                nodeIds.add(domId);
            }
            const edgeId = `${apkNodeId}_${domId}`;
            if (!edgeIds.has(edgeId)) {
                newEdges.push({ id: edgeId, from: apkNodeId, to: domId, color: { color: 'rgba(249, 115, 22, 0.4)' } });
                edgeIds.add(edgeId);
            }
        });

        // 3. IP Nodes
        intel.ips.forEach(ip => {
            const ipId = `ip_${ip}`;
            if (!nodeIds.has(ipId)) {
                newNodes.push({
                    id: ipId,
                    label: ip,
                    shape: 'dot',
                    size: 15,
                    color: { background: '#eab308', border: '#a16207', highlight: { background: '#facc15', border: '#eab308' } },
                    font: { color: '#ffffff' },
                    group: 'ip',
                    details: { address: ip, domains: intel.domains }
                });
                nodeIds.add(ipId);
            }
            const edgeId = `${apkNodeId}_${ipId}`;
            if (!edgeIds.has(edgeId)) {
                newEdges.push({ id: edgeId, from: apkNodeId, to: ipId, color: { color: 'rgba(234, 179, 8, 0.4)' } });
                edgeIds.add(edgeId);
            }
        });

        // 4. Certificate Nodes
        const cert = intel.cert;
        if (cert) {
            const certId = `cert_${cert}`;
            if (!nodeIds.has(certId)) {
                newNodes.push({
                    id: certId,
                    label: cert,
                    shape: 'diamond',
                    color: { background: '#a855f7', border: '#7e22ce', highlight: { background: '#c084fc', border: '#a855f7' } },
                    font: { color: '#ffffff' },
                    group: 'cert',
                    details: { id: cert, apk: report.app_name }
                });
                nodeIds.add(certId);
            }
            const edgeId = `${apkNodeId}_${certId}`;
            if (!edgeIds.has(edgeId)) {
                newEdges.push({ id: edgeId, from: apkNodeId, to: certId, color: { color: 'rgba(168, 85, 247, 0.4)' } });
                edgeIds.add(edgeId);
            }
        }
    });
    
    nodes.clear();
    edges.clear();
    nodes.add(newNodes);
    edges.add(newEdges);
    
    if (network) network.fit();
}

function generateMockThreatData() {
    return [
        {
            id: 'mock-1',
            app_name: 'Cleaner Pro (Mock)',
            apk_hash: '5A1B2C3D4E5F6G7H8I9J0K',
            risk_score: 92,
            risk_level: 'DANGEROUS',
            detected_time: new Date().toISOString(),
            intel: {
                domains: ['malicious-cleaner.net', 'update-srv-check.io'],
                ips: ['45.122.33.19', '103.44.12.8'],
                cert: 'CERT-A8B9'
            }
        },
        {
            id: 'mock-2',
            app_name: 'Secure Wallet (Mock)',
            apk_hash: 'F9E8D7C6B5A4938271605B',
            risk_score: 85,
            risk_level: 'DANGEROUS',
            detected_time: new Date().toISOString(),
            intel: {
                domains: ['wallet-verify-auth.biz'],
                ips: ['192.141.66.12'],
                cert: 'CERT-F2E1'
            }
        }
    ];
}

// Display Details on Click
function displayNodeDetails(nodeData) {
    const panel = document.getElementById('panel-content');
    if (!panel) return;
    
    const type = nodeData.group.toUpperCase();
    let detailsHtml = '';
    
    if (nodeData.group === 'apk') {
        const report = nodeData.raw_data;
        const detectDate = new Date(report.detected_time);
        const formattedDate = !isNaN(detectDate.getTime()) ? detectDate.toLocaleString() : 'Unknown';
        
        detailsHtml = `
            <div class="detail-row"><div class="detail-label">APK Hash</div><div class="detail-value hash-text">${escapeHTML(report.apk_hash)}</div></div>
            <div class="detail-row"><div class="detail-label">Risk Score</div><div class="detail-value"><strong>${report.risk_score}</strong>/100</div></div>
            <div class="detail-row"><div class="detail-label">Risk Level</div><div class="detail-value">${escapeHTML(report.risk_level)}</div></div>
            <div class="detail-row"><div class="detail-label">First Seen</div><div class="detail-value">${formattedDate}</div></div>
        `;
    } else if (nodeData.group === 'domain') {
        detailsHtml = `
            <div class="detail-row"><div class="detail-label">Domain Name</div><div class="detail-value font-medium">${escapeHTML(nodeData.details.name)}</div></div>
            <div class="detail-row"><div class="detail-label">Related APK Count</div><div class="detail-value">1 (Current Network)</div></div>
        `;
    } else if (nodeData.group === 'ip') {
        detailsHtml = `
            <div class="detail-row"><div class="detail-label">IP Address</div><div class="detail-value font-medium">${escapeHTML(nodeData.details.address)}</div></div>
            <div class="detail-row"><div class="detail-label">Associated Domains</div><div class="detail-value">${nodeData.details.domains.join(', ')}</div></div>
        `;
    } else if (nodeData.group === 'cert') {
        detailsHtml = `
            <div class="detail-row"><div class="detail-label">Certificate ID</div><div class="detail-value hash-text">${escapeHTML(nodeData.details.id)}</div></div>
            <div class="detail-row"><div class="detail-label">APK Associations</div><div class="detail-value">${escapeHTML(nodeData.details.apk)}</div></div>
        `;
    }
    
    panel.innerHTML = `
        <div class="detail-row" style="margin-bottom: 1.5rem; border-bottom: 1px solid var(--border-color); padding-bottom: 1rem;">
            <div class="detail-label">Node Type</div>
            <div class="detail-value"><span class="badge" style="background: rgba(34, 211, 238, 0.1); color: var(--accent-cyan); border: 1px solid rgba(34, 211, 238, 0.2);">${type}</span></div>
        </div>
        ${detailsHtml}
    `;
}

// Export Logic
if (btnExport) {
    btnExport.addEventListener('click', () => {
        let csvContent = "data:text/csv;charset=utf-8,";
        csvContent += "APK Name,Hash,Risk Level,Risk Score,Detection Time,Domains,IPs,Certificate\n";
        filteredData.forEach(r => {
            const d = r.intel ? r.intel.domains.join(';') : '';
            const ip = r.intel ? r.intel.ips.join(';') : '';
            const cert = r.intel ? r.intel.cert : '';
            const dt = new Date(r.detected_time).toISOString();
            const row = `"${r.app_name || ''}","${r.apk_hash || ''}","${r.risk_level || ''}","${r.risk_score || ''}","${dt}","${d}","${ip}","${cert}"`;
            csvContent += row + "\n";
        });
        const encodedUri = encodeURI(csvContent);
        const link = document.createElement("a");
        link.setAttribute("href", encodedUri);
        link.setAttribute("download", `threat_intelligence_export_${new Date().toISOString()}.csv`);
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    });
}

// Timeline Chart Logic
function updateTimeline() {
    const ctxElem = document.getElementById('timeline-chart');
    if (!ctxElem) return;
    const ctx = ctxElem.getContext('2d');
    
    // Group existing data by date
    const timeGroups = {};
    threatData.forEach(r => {
        if (!r.detected_time) return;
        const d = new Date(r.detected_time).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });
        timeGroups[d] = (timeGroups[d] || 0) + 1;
    });

    // Generate last 7 days for a professional, stable look
    const labels = [];
    const counts = [];
    for (let i = 6; i >= 0; i--) {
        const d = new Date();
        d.setDate(d.getDate() - i);
        const dateStr = d.toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });
        labels.push(dateStr);
        // Use real count if exists, else 0
        counts.push(timeGroups[dateStr] || 0);
    }
    
    if (timelineChart) {
        timelineChart.data.labels = labels;
        timelineChart.data.datasets[0].data = counts;
        timelineChart.update();
    } else {
        timelineChart = new Chart(ctx, {
            type: 'line',
            data: { 
                labels: labels, 
                datasets: [{ 
                    label: 'Threat Detections', 
                    data: counts, 
                    borderColor: '#22d3ee', 
                    backgroundColor: (context) => {
                        const chart = context.chart;
                        const {ctx, chartArea} = chart;
                        if (!chartArea) return null;
                        const gradient = ctx.createLinearGradient(0, chartArea.bottom, 0, chartArea.top);
                        gradient.addColorStop(0, 'rgba(34, 211, 238, 0)');
                        gradient.addColorStop(1, 'rgba(34, 211, 238, 0.2)');
                        return gradient;
                    }, 
                    borderWidth: 4, 
                    fill: true, 
                    tension: 0.45,
                    pointRadius: 4,
                    pointHoverRadius: 8,
                    pointBackgroundColor: '#22d3ee',
                    pointBorderColor: '#020617',
                    pointBorderWidth: 2
                }] 
            },
            options: { 
                responsive: true, 
                maintainAspectRatio: false, 
                plugins: {
                    tooltip: {
                        backgroundColor: '#0f172a',
                        titleFont: { size: 14, weight: 'bold' },
                        bodyFont: { size: 13 },
                        padding: 12,
                        cornerRadius: 8,
                        callbacks: {
                            title: (items) => `Date: ${items[0].label}`,
                            label: (item) => `Threats Detected: ${item.parsed.y}`
                        }
                    },
                    legend: { display: false }
                },
                scales: { 
                    y: { 
                        beginAtZero: true, 
                        grid: { color: 'rgba(148, 163, 184, 0.05)' },
                        ticks: { color: '#94a3b8', precision: 0, font: { family: 'Inter', size: 11 } } 
                    },
                    x: {
                        grid: { display: false },
                        ticks: { color: '#94a3b8', font: { family: 'Inter', size: 11 } }
                    }
                } 
            }
        });
    }
}

// Event Listeners
if (graphFocusSelect) {
    graphFocusSelect.addEventListener('change', (e) => {
        selectedGraphId = e.target.value;
        updateGraphData();
    });
}

if (searchInput) searchInput.addEventListener('input', () => { applyFiltersAndSort(); renderTable(); });
if (sortSelect) sortSelect.addEventListener('change', () => { applyFiltersAndSort(); renderTable(); });

// Awareness Generator Logic
function updateLivePreview() {
    const content = advisoryEditor.value;
    charCounter.textContent = `${content.length} characters`;
    
    if (unifiedPostBody) unifiedPostBody.textContent = content;
    
    // Auto-save draft
    localStorage.setItem('awareness_draft', content);
    draftStatus.textContent = 'Draft auto-saved';
    
    // Update Poster
    drawPoster();
}

function drawPoster() {
    if (!posterCanvas) return;
    const ctx = posterCanvas.getContext('2d');
    const apkId = apkAlertSelect.value;
    const report = threatData.find(r => r.id === apkId);
    
    // Clear with Cyber Background
    ctx.fillStyle = '#020617';
    ctx.fillRect(0, 0, 600, 600);
    
    // Grid Lines for Tech Effect
    ctx.strokeStyle = 'rgba(34, 211, 238, 0.05)';
    ctx.lineWidth = 1;
    for(let i=0; i<600; i+=40) {
        ctx.beginPath(); ctx.moveTo(i, 0); ctx.lineTo(i, 600); ctx.stroke();
        ctx.beginPath(); ctx.moveTo(0, i); ctx.lineTo(600, i); ctx.stroke();
    }

    // Header
    const gradient = ctx.createLinearGradient(0, 0, 600, 0);
    gradient.addColorStop(0, '#ef4444');
    gradient.addColorStop(1, '#991b1b');
    ctx.fillStyle = gradient;
    ctx.fillRect(0, 0, 600, 120);
    
    ctx.fillStyle = 'white';
    ctx.font = '800 38px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('PUBLIC SAFETY ALERT', 300, 60);
    ctx.font = '500 18px Inter, sans-serif';
    ctx.fillText('CYBER FRAUD INTELLIGENCE UNIT', 300, 95);
    
    // App Info Card Effect
    ctx.fillStyle = 'rgba(15, 23, 42, 0.8)';
    ctx.roundRect ? ctx.roundRect(40, 150, 520, 100, 12) : ctx.fillRect(40, 150, 520, 100);
    ctx.fill();
    ctx.strokeStyle = 'rgba(239, 68, 68, 0.3)';
    ctx.stroke();

    ctx.textAlign = 'left';
    ctx.fillStyle = '#94a3b8';
    ctx.font = '700 16px Inter, sans-serif';
    ctx.fillText('TARGET APPLICATION', 70, 185);
    
    ctx.fillStyle = 'white';
    ctx.font = '800 28px Inter, sans-serif';
    ctx.fillText(report ? report.app_name : 'No APK Selected', 70, 225);
    
    ctx.fillStyle = '#ef4444';
    ctx.font = '800 16px Inter, sans-serif';
    ctx.textAlign = 'right';
    ctx.fillText('STATUS: DANGEROUS', 530, 185);
    
    // Advisory Body
    ctx.textAlign = 'left';
    ctx.fillStyle = '#f8fafc';
    ctx.font = '500 20px Inter, sans-serif';
    const lines = wrapText(ctx, advisoryEditor.value || 'Drafting secure advisory message...', 520);
    let y = 300;
    lines.forEach(line => {
        ctx.fillText(line, 40, y);
        y += 32;
    });
    
    // Footer
    ctx.fillStyle = 'rgba(34, 211, 238, 0.1)';
    ctx.fillRect(0, 530, 600, 70);
    ctx.fillStyle = '#22d3ee';
    ctx.font = '800 16px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('SECURE YOUR DEVICE • REPORT SUSPICIOUS APKS', 300, 575);
}

function wrapText(ctx, text, maxWidth) {
    const words = text.split(' ');
    const lines = [];
    let currentLine = words[0];

    for (let i = 1; i < words.length; i++) {
        const word = words[i];
        const width = ctx.measureText(currentLine + " " + word).width;
        if (width < maxWidth) {
            currentLine += " " + word;
        } else {
            lines.push(currentLine);
            currentLine = word;
        }
    }
    lines.push(currentLine);
    return lines;
}

btnGenerateTemplate.addEventListener('click', () => {
    const apkId = apkAlertSelect.value;
    if (!apkId) {
        alert('Please select a dangerous APK first.');
        return;
    }
    
    const report = threatData.find(r => r.id === apkId);
    const perms = report.permissions ? report.permissions.split(',').slice(0, 3).map(p => `• ${p.trim()}`).join('\n') : '• Unusual background activity';
    
    const template = `⚠ CYBER SAFETY ALERT

A dangerous APK has been detected.

App Name:
${report.app_name}

Risk Level:
DANGEROUS

This application may:
${perms}

Users are advised:
• Do NOT install this APK
• Remove immediately if installed
• Report suspicious apps using APK Guard

Stay Alert. Stay Safe.`;

    advisoryEditor.value = template;
    updateLivePreview();
});

if (advisoryEditor) advisoryEditor.addEventListener('input', updateLivePreview);

// Remove tab switching logic as it's no longer needed

btnCopyPost.addEventListener('click', () => {
    advisoryEditor.select();
    document.execCommand('copy');
    const originalText = btnCopyPost.innerHTML;
    btnCopyPost.innerHTML = '<i class="fa-solid fa-check"></i> Copied!';
    setTimeout(() => { btnCopyPost.innerHTML = originalText; }, 2000);
});

btnDownloadPoster.addEventListener('click', () => {
    const link = document.createElement('a');
    link.download = `awareness_poster_${new Date().getTime()}.png`;
    link.href = posterCanvas.toDataURL();
    link.click();
});

btnPublishAdvisory.addEventListener('click', async () => {
    const apkId = apkAlertSelect.value;
    const content = advisoryEditor.value;
    
    if (!apkId || !content) {
        alert('Please select an APK and write an advisory.');
        return;
    }
    
    const report = threatData.find(r => r.id === apkId);
    
    try {
        btnPublishAdvisory.disabled = true;
        btnPublishAdvisory.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Publishing...';
        
        const response = await fetch(`${SUPABASE_URL}/rest/v1/awareness_posts`, {
            method: 'POST',
            headers: {
                'apikey': SUPABASE_KEY,
                'Authorization': `Bearer ${SUPABASE_KEY}`,
                'Content-Type': 'application/json',
                'Prefer': 'return=representation'
            },
            body: JSON.stringify({
                app_name: report.app_name,
                post_content: content,
                created_time: new Date().toISOString()
            })
        });
        
        if (!response.ok) throw new Error('Failed to publish');
        
        alert('Public Advisory Published Successfully!');
        fetchAwarenessHistory();
        advisoryEditor.value = '';
        updateLivePreview();
        
    } catch (error) {
        console.error('Publish error:', error);
        alert('Error publishing advisory. Ensure the awareness_posts table exists in Supabase.');
    } finally {
        btnPublishAdvisory.disabled = false;
        btnPublishAdvisory.innerHTML = '<i class="fa-solid fa-paper-plane"></i> Publish Advisory';
    }
});

async function fetchAwarenessHistory() {
    try {
        const response = await fetch(`${SUPABASE_URL}/rest/v1/awareness_posts?select=*&order=created_time.desc&limit=10`, {
            headers: {
                'apikey': SUPABASE_KEY,
                'Authorization': `Bearer ${SUPABASE_KEY}`
            }
        });
        
        if (!response.ok) return;
        const history = await response.json();
        
        if (history.length > 0) {
            awarenessHistoryList.innerHTML = '';
            history.forEach(post => {
                const card = document.createElement('div');
                card.className = 'history-card DANGEROUS';
                card.innerHTML = `
                    <div class="history-header">
                        <span class="history-app">${escapeHTML(post.app_name)}</span>
                        <span class="history-time">${new Date(post.created_time).toLocaleString()}</span>
                    </div>
                    <div class="history-content">${escapeHTML(post.post_content)}</div>
                `;
                awarenessHistoryList.appendChild(card);
            });
        }
    } catch (e) {
        console.error('History fetch error:', e);
    }
}

// Clear draft on start to prevent showing stale or autogenerated messages without a selected threat
if (advisoryEditor) {
    advisoryEditor.value = '';
    updateLivePreview();
}

fetchAwarenessHistory();

// Initialization
initGraph();
fetchThreatReports();
setInterval(fetchThreatReports, 5000);
setInterval(fetchAwarenessHistory, 30000); // Refresh history every 30s
// Blacklist Feature Implementation
async function blacklistApk(btn, hash, name, risk) {
    if (!hash || hash === 'N/A') return;
    
    // 1. Check local state first for instant feedback
    if (blacklistedHashes.has(hash)) {
        alert("This APK is already blacklisted");
        return;
    }

    const officer = localStorage.getItem('policeUser');
    const officerName = officer ? JSON.parse(officer).username : 'Anonymous Officer';

    try {
        // 2. Check Supabase for existing entry (Double verification)
        const checkRes = await fetch(`${SUPABASE_URL}/rest/v1/apk_blacklist?apk_hash=eq.${hash}`, {
            headers: {
                'apikey': SUPABASE_KEY,
                'Authorization': `Bearer ${SUPABASE_KEY}`
            }
        });
        const existing = await checkRes.json();
        
        if (existing.length > 0) {
            alert("This APK is already blacklisted");
            blacklistedHashes.add(hash);
            btn.innerText = '✔ Blacklisted';
            btn.disabled = true;
            btn.style.background = '#1e293b';
            return;
        }

        // 3. Insert into Blacklist
        const response = await fetch(`${SUPABASE_URL}/rest/v1/apk_blacklist`, {
            method: 'POST',
            headers: {
                'apikey': SUPABASE_KEY,
                'Authorization': `Bearer ${SUPABASE_KEY}`,
                'Content-Type': 'application/json',
                'Prefer': 'return=minimal'
            },
            body: JSON.stringify({
                apk_hash: hash,
                app_name: name,
                risk_level: risk,
                blocked_by: officerName,
                blocked_time: new Date().toISOString()
            })
        });

        if (response.ok) {
            alert("APK Successfully Blacklisted");
            blacklistedHashes.add(hash);
            btn.innerText = '✔ Blacklisted';
            btn.disabled = true;
            btn.style.background = '#1e293b';
            updateBlacklistStats();
        } else {
            console.error('Blacklist failed:', await response.text());
        }
    } catch (error) {
        console.error('Blacklist error:', error);
    }
}

async function fetchBlacklistData() {
    try {
        const res = await fetch(`${SUPABASE_URL}/rest/v1/apk_blacklist?select=apk_hash`, {
            headers: {
                'apikey': SUPABASE_KEY,
                'Authorization': `Bearer ${SUPABASE_KEY}`
            }
        });
        const data = await res.json();
        blacklistedHashes = new Set(data.map(item => item.apk_hash));
        updateBlacklistStats();
    } catch (error) {
        console.error('Error fetching blacklist:', error);
    }
}

function updateBlacklistStats() {
    if (statBlacklistCount) {
        animateValue(statBlacklistCount, parseInt(statBlacklistCount.innerText) || 0, blacklistedHashes.size, 500);
    }
}

function deleteThreat(id) {
    if (confirm('Are you sure you want to remove this threat from the intelligence display?')) {
        dismissedThreatIds.add(id);
        localStorage.setItem('dismissedThreats', JSON.stringify(Array.from(dismissedThreatIds)));
        
        // Remove from current data and re-render
        threatData = threatData.filter(r => r.id !== id);
        processAndRenderData();
    }
}

// Initial Fetch for Blacklist
fetchBlacklistData();
// Social Media Sharing Integration
function shareToPlatform(platform) {
    const message = document.getElementById("advisory-editor").value;

    if (!message) {
        alert("Please write advisory content first.");
        return;
    }

    let url = "";

    if (platform === "twitter") {
        url = "https://twitter.com/intent/tweet?text=" + encodeURIComponent(message);
        window.open(url, "_blank");
    } else if (platform === "facebook") {
        url = "https://www.facebook.com/sharer/sharer.php?u=" + encodeURIComponent("https://cyber-alert.local");
        window.open(url, "_blank");
    } else if (platform === "instagram") {
        navigator.clipboard.writeText(message).then(() => {
            alert("Message copied. Opening Instagram. Paste caption.");
            window.open("https://www.instagram.com/", "_blank");
        }).catch(err => {
            console.error('Could not copy text: ', err);
        });
    }
}
