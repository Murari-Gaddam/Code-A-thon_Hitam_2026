/**
 * AEGIS / VERITAS // NIDS AGENT - SOC ANALYST JAVASCRIPT ENGINE
 * Strict Minimal Palette:
 * - Charcoal: #262626
 * - Ash Grey: #acbfa4
 * - Tangerine: #ff7f11
 * - Crimson Red: #ff1b1c
 * - Cream / Soft Cream: #e2e8ce / #f5f6ed
 * ZERO pure white or pure black
 */

(function () {
  'use strict';

  // ==========================================================================
  // 1. STATE MANAGEMENT & CONSTANTS
  // ==========================================================================
  const MAX_BUFFER_SIZE = 100;
  let flowBuffer = [];
  let isStreamPaused = false;
  let streamIntervalMs = 1000;
  let streamTimer = null;
  let activeFilterMode = 'ALL'; // 'ALL' | 'ATTACKS'
  let activeSearchQuery = '';
  let activeChipFilter = null;
  let selectedFlowId = null;
  let totalPacketsTaken = 0;
  let isAudioMuted = true;
  let quarantinedHosts = new Map(); // ip -> { ip, reason, timestamp, rule }
  let currentActiveSourceName = 'None';
  let uploadedParsedRecords = [];

  // Threat Classifier aggregate counters
  let classifierTotals = {
    'ABNORMAL_TCP_FLAGS': 0,
    'SYN_FLOOD': 0,
    'PORT_SCAN': 0,
    'DNS_TUNNELING': 0,
    'SSH_BRUTE_FORCE': 0,
    'ICMP_EXFILTRATION': 0
  };

  // Sound Engine (Web Audio API synthetic beeps)
  let audioCtx = null;
  function playThreatTone(isCritical = false) {
    if (isAudioMuted) return;
    try {
      if (!audioCtx) {
        audioCtx = new (window.AudioContext || window.webkitAudioContext)();
      }
      if (audioCtx.state === 'suspended') {
        audioCtx.resume();
      }
      const osc = audioCtx.createOscillator();
      const gain = audioCtx.createGain();
      osc.type = isCritical ? 'sawtooth' : 'sine';
      osc.frequency.setValueAtTime(isCritical ? 880 : 540, audioCtx.currentTime);
      if (isCritical) {
        osc.frequency.exponentialRampToValueAtTime(440, audioCtx.currentTime + 0.18);
      }
      gain.gain.setValueAtTime(0.08, audioCtx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.2);
      osc.connect(gain);
      gain.connect(audioCtx.destination);
      osc.start();
      osc.stop(audioCtx.currentTime + 0.2);
    } catch (e) {
      console.warn('WebAudio playback suppressed:', e);
    }
  }

  // ==========================================================================
  // 2. REALISTIC NETWORK SIGNATURE & FLOW GENERATOR
  // ==========================================================================
  const INTERNAL_HOSTS = [
    { ip: '172.16.0.42', tag: 'VLAN 10 // DB-CORE' },
    { ip: '172.16.0.89', tag: 'VLAN 10 // APP-SVR' },
    { ip: '192.168.1.104', tag: 'DEV-LAN // WORKSTATION' },
    { ip: '10.0.4.15', tag: 'DMZ // NGINX-EDGE' },
    { ip: '10.0.12.80', tag: 'PROD // K8S-INGRESS' },
    { ip: '192.168.1.55', tag: 'FIN-LAN // AGENT-04' },
    { ip: '172.16.2.11', tag: 'VLAN 20 // S3-PROXY' }
  ];

  const EXTERNAL_BENIGN = [
    { ip: '142.250.190.46', port: 443, service: 'GOOGLE-CLOUD-CDN', geo: 'AS15169 (US)' },
    { ip: '151.101.65.140', port: 443, service: 'FASTLY-EDGE-TLS', geo: 'AS54113 (EU)' },
    { ip: '13.107.42.16', port: 443, service: 'MICROSOFT-AZURE', geo: 'AS8075 (US)' },
    { ip: '8.8.8.8', port: 53, service: 'GOOGLE-PUBLIC-DNS', geo: 'AS15169 (GLOBAL)' },
    { ip: '1.1.1.1', port: 53, service: 'CLOUDFLARE-DNS', geo: 'AS13335 (GLOBAL)' },
    { ip: '17.253.144.10', port: 123, service: 'NTP-TIME-STANDARD', geo: 'AS714 (US)' }
  ];

  const ATTACK_TEMPLATES = [
    {
      type: 'ABNORMAL_TCP_FLAGS',
      severity: 'suspicious', // warning / tangerine
      protocol: 'TCP (6)',
      baseConfidence: 89.2,
      flags: ['SYN', 'FIN', 'PSH', 'URG'],
      geo: 'AS49505 (RU / BULLETPROOF)',
      entropy: 5.42,
      asymmetry: 0.78,
      desc: 'TCP header anomaly detected: Incompatible FIN+PSH+URG (Xmas Tree Scan). Flow discarded.',
      targetPorts: [80, 443, 8080, 22]
    },
    {
      type: 'SYN_FLOOD',
      severity: 'malicious', // critical / crimson red
      protocol: 'TCP (6)',
      baseConfidence: 98.7,
      flags: ['SYN'],
      geo: 'AS209 (US / COMPROMISED-NODE)',
      entropy: 3.12,
      asymmetry: 0.96,
      desc: 'High-frequency half-open SYN packets without completing handshake. Ingress rate spike.',
      targetPorts: [80, 443, 8443]
    },
    {
      type: 'PORT_SCAN',
      severity: 'suspicious', // warning / tangerine
      protocol: 'TCP (6)',
      baseConfidence: 92.4,
      flags: ['SYN'],
      geo: 'AS16276 (FR / OVH-HOST)',
      entropy: 4.88,
      asymmetry: 0.85,
      desc: 'Rapid horizontal sequence traversal across standard service ports (1-1024).',
      targetPorts: [21, 22, 23, 25, 80, 443, 3389, 8080]
    },
    {
      type: 'DNS_TUNNELING',
      severity: 'malicious', // critical / crimson red
      protocol: 'UDP (17)',
      baseConfidence: 97.5,
      flags: [],
      geo: 'AS4837 (CN / TRANSIT)',
      entropy: 7.91,
      asymmetry: 0.91,
      desc: 'Base64 obfuscated payload detected inside TXT record queries. Data exfiltration channel.',
      targetPorts: [53]
    },
    {
      type: 'SSH_BRUTE_FORCE',
      severity: 'malicious', // critical / crimson red
      protocol: 'TCP (6)',
      baseConfidence: 96.8,
      flags: ['SYN', 'ACK', 'PSH'],
      geo: 'AS9009 (NL / HOSTING)',
      entropy: 6.74,
      asymmetry: 0.72,
      desc: 'High velocity credential stuffing and failed key exchanges on port 22.',
      targetPorts: [22]
    },
    {
      type: 'ICMP_EXFILTRATION',
      severity: 'suspicious', // warning / tangerine
      protocol: 'ICMP (1)',
      baseConfidence: 86.9,
      flags: [],
      geo: 'AS3356 (US / LEVEL3)',
      entropy: 7.45,
      asymmetry: 0.89,
      desc: 'Oversized ICMP echo packets exceeding standard 64-byte payload. Steganographic carrier.',
      targetPorts: [0]
    }
  ];

  const BENIGN_TEMPLATES = [
    {
      type: 'TLS_ENCRYPTED_STREAM',
      severity: 'normal',
      protocol: 'TCP (6)',
      baseConfidence: 99.2,
      flags: ['ACK', 'PSH'],
      entropy: 7.65,
      asymmetry: 0.45,
      desc: 'Standard TLS 1.3 encrypted application layer flow. Valid handshake certificates.'
    },
    {
      type: 'DNS_STANDARD_QUERY',
      severity: 'normal',
      protocol: 'UDP (17)',
      baseConfidence: 98.4,
      flags: [],
      entropy: 3.82,
      asymmetry: 0.12,
      desc: 'Standard DNS recursive resolver lookup for verified domain suffix.'
    },
    {
      type: 'NTP_TIME_SYNC_NOMINAL',
      severity: 'normal',
      protocol: 'UDP (17)',
      baseConfidence: 99.7,
      flags: [],
      entropy: 2.15,
      asymmetry: 0.05,
      desc: 'Network Time Protocol stratum-2 synchronization packet flow.'
    },
    {
      type: 'HTTP_REST_API_NOMINAL',
      severity: 'normal',
      protocol: 'TCP (6)',
      baseConfidence: 97.8,
      flags: ['ACK', 'PSH'],
      entropy: 5.12,
      asymmetry: 0.48,
      desc: 'Authenticated microservice REST JSON response over internal gateway.'
    }
  ];

  function randomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
  }

  function randomChoice(arr) {
    return arr[Math.floor(Math.random() * arr.length)];
  }

  function formatUtcTimestamp(date) {
    const hours = String(date.getUTCHours()).padStart(2, '0');
    const minutes = String(date.getUTCMinutes()).padStart(2, '0');
    const seconds = String(date.getUTCSeconds()).padStart(2, '0');
    const millis = String(date.getUTCMilliseconds()).padStart(3, '0');
    return `${hours}:${minutes}:${seconds}.${millis}`;
  }

  function generateHexSample(type, size) {
    let lines = [];
    const numLines = 3;
    for (let i = 0; i < numLines; i++) {
      let offset = (i * 16).toString(16).padStart(4, '0');
      let bytes = [];
      let ascii = '';
      for (let b = 0; b < 16; b++) {
        let byteVal = Math.floor(Math.random() * 256);
        bytes.push(byteVal.toString(16).padStart(2, '0'));
        ascii += (byteVal >= 32 && byteVal <= 126) ? String.fromCharCode(byteVal) : '.';
      }
      let byteStr = bytes.slice(0, 8).join(' ') + '  ' + bytes.slice(8).join(' ');
      lines.push(`${offset}  ${byteStr.padEnd(49, ' ')}  ${ascii}`);
    }
    return lines.join('\n');
  }

  function generatePacketFlow(forcedTemplate = null) {
    const now = new Date();
    const timestampStr = formatUtcTimestamp(now);
    
    let template;
    let isAttack = false;

    if (forcedTemplate) {
      template = forcedTemplate;
      isAttack = (template.severity !== 'normal');
    } else {
      // Standard random distribution: 78% normal, 14% suspicious, 8% malicious
      const roll = Math.random();
      if (roll < 0.78) {
        template = randomChoice(BENIGN_TEMPLATES);
      } else {
        isAttack = true;
        template = randomChoice(ATTACK_TEMPLATES);
      }
    }

    if (isAttack && classifierTotals[template.type] !== undefined) {
      classifierTotals[template.type]++;
    }

    const internalHost = randomChoice(INTERNAL_HOSTS);
    let srcIp, srcPort, srcTag, dstIp, dstPort, dstTag, geo;

    if (isAttack) {
      const isInternalSource = Math.random() < 0.25;
      if (isInternalSource) {
        srcIp = internalHost.ip;
        srcPort = randomInt(40000, 65000);
        srcTag = internalHost.tag;
        const target = randomChoice(INTERNAL_HOSTS.filter(h => h.ip !== internalHost.ip));
        dstIp = target.ip;
        dstPort = randomChoice(template.targetPorts || [80]);
        dstTag = target.tag;
      } else {
        srcIp = `${randomInt(45, 198)}.${randomInt(10, 240)}.${randomInt(1, 254)}.${randomInt(2, 250)}`;
        srcPort = randomInt(1025, 65530);
        srcTag = `EXTERNAL WAN // ${(template.geo || 'GEO-NET').split(' ')[0]}`;
        dstIp = internalHost.ip;
        dstPort = randomChoice(template.targetPorts || [80]);
        dstTag = internalHost.tag;
      }
      geo = template.geo || 'AS15169 (US)';
    } else {
      const external = randomChoice(EXTERNAL_BENIGN);
      srcIp = internalHost.ip;
      srcPort = randomInt(49152, 65535);
      srcTag = internalHost.tag;
      dstIp = external.ip;
      dstPort = external.port;
      dstTag = external.service;
      geo = external.geo;
    }

    const confidence = Math.min(99.9, +(template.baseConfidence + (Math.random() * 2 - 1)).toFixed(1));
    const flowId = 'FK-' + Math.floor(1000000 + Math.random() * 9000000);
    const duration = randomInt(12, 1200);
    const packetSize = randomInt(64, 1500);
    const ttl = randomInt(48, 128);

    const isHostQuarantined = quarantinedHosts.has(srcIp) || quarantinedHosts.has(dstIp);

    return {
      id: flowId,
      timestamp: timestampStr,
      date: now,
      srcIp: `${srcIp}:${srcPort}`,
      rawSrcIp: srcIp,
      srcPort: srcPort,
      srcTag: srcTag,
      dstIp: `${dstIp}:${dstPort}`,
      rawDstIp: dstIp,
      dstPort: dstPort,
      dstTag: dstTag,
      attackType: template.type,
      severity: template.severity,
      confidence: confidence,
      protocol: template.protocol,
      durationMs: duration,
      packetSize: packetSize,
      ttl: ttl,
      geo: geo,
      tcpFlags: template.flags || [],
      windowSize: randomInt(1024, 65535),
      seq: '0x' + Math.floor(Math.random() * 0xFFFFFFFF).toString(16).toUpperCase(),
      ack: (template.flags || []).includes('ACK') ? '0x' + Math.floor(Math.random() * 0xFFFFFFFF).toString(16).toUpperCase() : '0x00000000',
      entropy: +(template.entropy + (Math.random() * 0.1 - 0.05)).toFixed(2),
      asymmetry: +(template.asymmetry + (Math.random() * 0.04 - 0.02)).toFixed(2),
      desc: template.desc,
      rawHex: generateHexSample(template.type, packetSize),
      isQuarantined: isHostQuarantined
    };
  }

  // ==========================================================================
  // 3. UI RENDERING & DOM UPDATES
  // ==========================================================================
  // Views
  const viewIngestion = document.getElementById('view-ingestion');
  const viewDashboard = document.getElementById('view-dashboard');
  const navIngestionBtn = document.getElementById('nav-ingestion-btn');
  const btnSwitchSource = document.getElementById('btn-switch-source');
  const brandHomeLink = document.getElementById('brand-home-link');
  const activeSourceName = document.getElementById('active-source-name');
  const activeSourceStatus = document.getElementById('active-source-status');

  // Header Elements
  const utcClockElem = document.getElementById('utc-clock');
  const packetCounterElem = document.getElementById('packet-counter');
  const quarantineCountBadge = document.getElementById('quarantine-count');
  const quarantineBtn = document.getElementById('quarantine-btn');
  const quarantineStatusLine = document.getElementById('quarantine-status-line');
  const toastContainer = document.getElementById('toast-container');

  // Ingestion View Elements
  const csvDropzone = document.getElementById('csv-dropzone');
  const csvFileInput = document.getElementById('csv-file-input');
  const selectedFileLabel = document.getElementById('selected-file-label');
  const btnAnalyzeCsv = document.getElementById('btn-analyze-csv');
  const btnAnalyzeText = document.getElementById('btn-analyze-text');
  const btnConnectServer = document.getElementById('btn-connect-server');
  const btnConnectText = document.getElementById('btn-connect-text');
  const serverIpInput = document.getElementById('server-ip-input');
  const serverUserInput = document.getElementById('server-user-input');
  const serverPassInput = document.getElementById('server-pass-input');
  const serverPathInput = document.getElementById('server-path-input');

  // Dashboard Overview elements
  const tbody = document.getElementById('traffic-tbody');
  const riskScoreValueElem = document.getElementById('risk-score-value');
  const riskScoreEvalElem = document.getElementById('risk-score-eval');
  const threatPostureTextElem = document.getElementById('threat-posture-text');
  const gaugeMeter = document.getElementById('gauge-meter');
  const eventsCountDisplay = document.getElementById('events-count-display');
  const streamToggleBtn = document.getElementById('stream-toggle-btn');
  const streamBtnIcon = document.getElementById('stream-btn-icon');
  const streamBtnText = document.getElementById('stream-btn-text');
  const filterSearchInput = document.getElementById('filter-search-input');
  const clearSearchBtn = document.getElementById('clear-search-btn');

  // Preprocessing DOM elements
  const progNormal = document.getElementById('prog-normal');
  const progSuspicious = document.getElementById('prog-suspicious');
  const progMalicious = document.getElementById('prog-malicious');
  const pctNormal = document.getElementById('pct-normal');
  const pctSuspicious = document.getElementById('pct-suspicious');
  const pctMalicious = document.getElementById('pct-malicious');
  const countNormal = document.getElementById('count-normal');
  const countSuspicious = document.getElementById('count-suspicious');
  const countMalicious = document.getElementById('count-malicious');

  // Classifier chip counters
  const chipAbnormal = document.getElementById('count-chip-abnormal-flags');
  const chipSynFlood = document.getElementById('count-chip-syn-flood');
  const chipPortScan = document.getElementById('count-chip-port-scan');
  const chipDnsTunnel = document.getElementById('count-chip-dns-tunnel');
  const chipSshBrute = document.getElementById('count-chip-ssh-brute');
  const chipIcmpExfil = document.getElementById('count-chip-icmp-exfil');

  // Inspection Drawer elements
  const drawer = document.getElementById('inspection-drawer');
  const drawerCloseBtn = document.getElementById('drawer-close-btn');
  const drawerTitle = document.getElementById('drawer-title');
  const drawerSeverityBanner = document.getElementById('drawer-severity-banner');
  const drawerSeverityHeading = document.getElementById('drawer-severity-heading');
  const drawerSeverityDesc = document.getElementById('drawer-severity-desc');
  const btnQuarantineHost = document.getElementById('btn-quarantine-host');
  const quarantineBtnLabel = document.getElementById('quarantine-btn-label');
  const btnCopySnort = document.getElementById('btn-copy-snort');
  const btnExportPcap = document.getElementById('btn-export-pcap');

  const detailTimestamp = document.getElementById('detail-timestamp');
  const detailProtocol = document.getElementById('detail-protocol');
  const detailDuration = document.getElementById('detail-duration');
  const detailSize = document.getElementById('detail-size');
  const detailTtl = document.getElementById('detail-ttl');
  const detailGeo = document.getElementById('detail-geo');
  const detailSrcIp = document.getElementById('detail-src-ip');
  const detailSrcType = document.getElementById('detail-src-type');
  const detailDstIp = document.getElementById('detail-dst-ip');
  const detailDstType = document.getElementById('detail-dst-type');
  const detailWindowSize = document.getElementById('detail-window-size');
  const detailSeq = document.getElementById('detail-seq');
  const detailAck = document.getElementById('detail-ack');
  const detailEntropy = document.getElementById('detail-entropy');
  const detailEntropyBar = document.getElementById('detail-entropy-bar');
  const detailAsymmetry = document.getElementById('detail-asymmetry');
  const detailAsymmetryBar = document.getElementById('detail-asymmetry-bar');
  const detailConfidenceText = document.getElementById('detail-confidence-text');
  const detailConfidenceBar = document.getElementById('detail-confidence-bar');
  const detailRawHex = document.getElementById('detail-raw-hex');

  // TCP flag pills in drawer
  const flagElements = {
    SYN: document.getElementById('flag-syn'),
    ACK: document.getElementById('flag-ack'),
    RST: document.getElementById('flag-rst'),
    FIN: document.getElementById('flag-fin'),
    PSH: document.getElementById('flag-psh'),
    URG: document.getElementById('flag-urg')
  };

  // Quarantine Modal elements
  const quarantineModal = document.getElementById('quarantine-modal');
  const modalCloseBtn = document.getElementById('modal-close-btn');
  const modalDoneBtn = document.getElementById('modal-done-btn');
  const modalClearAllBtn = document.getElementById('modal-clear-all-btn');
  const quarantineTbody = document.getElementById('quarantine-tbody');

  // ==========================================================================
  // 4. LIVE UTC CLOCK & COUNTER TICKERS
  // ==========================================================================
  function updateLiveClock() {
    const now = new Date();
    const hours = String(now.getUTCHours()).padStart(2, '0');
    const minutes = String(now.getUTCMinutes()).padStart(2, '0');
    const seconds = String(now.getUTCSeconds()).padStart(2, '0');
    const millis = String(now.getUTCMilliseconds()).padStart(3, '0');
    utcClockElem.textContent = `${hours}:${minutes}:${seconds}.${millis} UTC`;
  }
  setInterval(updateLiveClock, 35);

  // ==========================================================================
  // 5. VIEW NAVIGATION & ROUTING
  // ==========================================================================
  function showIngestionView() {
    viewDashboard.classList.add('hidden');
    viewIngestion.classList.remove('hidden');
    navIngestionBtn.classList.add('hidden');

    if (streamTimer) {
      clearInterval(streamTimer);
      streamTimer = null;
    }
  }

  function showDashboardView(sourceName, sourceStatus, initialRecords = []) {
    currentActiveSourceName = sourceName;
    if (activeSourceName) activeSourceName.textContent = sourceName;
    if (activeSourceStatus) activeSourceStatus.textContent = sourceStatus;

    viewIngestion.classList.add('hidden');
    viewDashboard.classList.remove('hidden');
    navIngestionBtn.classList.remove('hidden');

    // Populate flowBuffer with the ingested data
    flowBuffer = [];
    // Reset classifier counters for new dataset
    for (let k in classifierTotals) {
      classifierTotals[k] = 0;
    }

    if (initialRecords && initialRecords.length > 0) {
      initialRecords.forEach(rec => {
        flowBuffer.push(rec);
        if (rec.severity !== 'normal' && classifierTotals[rec.attackType] !== undefined) {
          classifierTotals[rec.attackType]++;
        }
      });
      totalPacketsTaken = Math.max(flowBuffer.length * 150, 48200);
    } else {
      // Generate 25 realistic starter flows
      for (let i = 0; i < 25; i++) {
        flowBuffer.push(generatePacketFlow());
      }
      totalPacketsTaken = 85200;
    }

    packetCounterElem.textContent = totalPacketsTaken.toLocaleString();

    renderTable();
    updateFleetMetrics();
    updateQuarantineBadges();

    // Start background flow stream
    if (!isStreamPaused) {
      startStreamTimer();
    }

    showToast(`DATASET LOADED: ${sourceName}`, 'normal');
  }

  // ==========================================================================
  // 6. CSV PARSER & INGESTION LOGIC
  // ==========================================================================
  function parseCSVContent(csvText) {
    const lines = csvText.split(/\r?\n/).filter(line => line.trim().length > 0);
    if (lines.length < 2) {
      throw new Error('CSV file contains insufficient rows. At least header and 1 data row required.');
    }

    // Determine delimiter (comma, semicolon, or tab)
    const headerLine = lines[0];
    let delimiter = ',';
    if (headerLine.includes('\t')) delimiter = '\t';
    else if (headerLine.includes(';') && !headerLine.includes(',')) delimiter = ';';

    const headers = headerLine.split(delimiter).map(h => h.trim().toLowerCase().replace(/['"]/g, ''));
    
    // Map column indices
    const colTimestamp = headers.findIndex(h => h.includes('time') || h.includes('date'));
    const colSrcPort = headers.findIndex(h => (h.includes('src') || h.includes('source')) && h.includes('port'));
    const colSrcIp = headers.findIndex(h => (h.includes('src') || h.includes('source')) && (h.includes('ip') || h.includes('addr') || h.includes('host')));
    const colDstPort = headers.findIndex(h => (h.includes('dst') || h.includes('dest') || h.includes('target') || h.includes('destination')) && h.includes('port'));
    const colDstIp = headers.findIndex(h => (h.includes('dst') || h.includes('dest') || h.includes('target') || h.includes('destination')) && (h.includes('ip') || h.includes('addr') || h.includes('host')));
    const colAttack = headers.findIndex(h => h.includes('attack') || h.includes('label') || h.includes('class') || h.includes('threat') || h.includes('type'));
    const colConfidence = headers.findIndex(h => h.includes('conf') || h.includes('score') || h.includes('prob'));
    const colProtocol = headers.findIndex(h => h.includes('proto'));
    const colDuration = headers.findIndex(h => h.includes('duration'));
    const colPacketLen = headers.findIndex(h => h.includes('packet length mean') || h.includes('total length of fwd') || h.includes('length of fwd') || h.includes('size'));
    const colSynFlag = headers.findIndex(h => h.includes('syn flag'));
    const colAckFlag = headers.findIndex(h => h.includes('ack flag'));
    const colFinFlag = headers.findIndex(h => h.includes('fin flag'));
    const colPshFlag = headers.findIndex(h => h.includes('psh flag'));
    const colRstFlag = headers.findIndex(h => h.includes('rst flag'));
    const colUrgFlag = headers.findIndex(h => h.includes('urg flag'));

    const parsedRecords = [];
    const now = new Date();
    const knownThreatKeywords = ['normal', 'dos', 'portscan', 'brute force', 'web attack', 'benign'];

    for (let i = 1; i < lines.length; i++) {
      const row = lines[i].split(delimiter).map(c => c.trim().replace(/['"]/g, ''));
      if (row.length < 2) continue;

      let rawTimestamp = (colTimestamp >= 0 && row[colTimestamp]) 
        ? row[colTimestamp] 
        : formatUtcTimestamp(new Date(now.getTime() - (lines.length - i) * 600));
      
      // Determine Destination Port & IP
      let dstPortNum = (colDstPort >= 0 && row[colDstPort]) ? (parseInt(row[colDstPort], 10) || 80) : randomInt(80, 8080);
      let rawDst = '10.0.4.15';
      if (colDstIp >= 0 && row[colDstIp] && row[colDstIp].includes('.')) {
        rawDst = row[colDstIp];
      } else if (dstPortNum === 53) {
        rawDst = '8.8.8.8';
      } else if (dstPortNum === 80 || dstPortNum === 8080) {
        rawDst = '10.0.4.15';
      } else if (dstPortNum === 443) {
        rawDst = '142.250.190.46';
      } else if (dstPortNum === 22) {
        rawDst = '172.16.0.42';
      } else {
        rawDst = '192.168.1.' + (100 + (dstPortNum % 100));
      }
      let dstWithPort = rawDst.includes(':') ? rawDst : (rawDst + ':' + dstPortNum);

      // Determine Source Port & IP
      let srcPortNum = (colSrcPort >= 0 && row[colSrcPort]) ? (parseInt(row[colSrcPort], 10) || 49210) : randomInt(30000, 65000);
      let rawSrc = '172.16.0.' + ((i % 80) + 10);
      if (colSrcIp >= 0 && row[colSrcIp] && row[colSrcIp].includes('.')) {
        rawSrc = row[colSrcIp];
      }
      let srcWithPort = rawSrc.includes(':') ? rawSrc : (rawSrc + ':' + srcPortNum);

      // Robust Attack Type extraction with boundary safety
      let rawAttack = null;
      if (colAttack >= 0 && colAttack < row.length && row[colAttack]) {
        rawAttack = row[colAttack];
      } else {
        // Search trailing elements for label
        for (let k = row.length - 1; k >= Math.max(0, row.length - 4); k--) {
          const val = (row[k] || '').toLowerCase();
          if (knownThreatKeywords.some(kw => val.includes(kw))) {
            rawAttack = row[k];
            break;
          }
        }
        if (!rawAttack && row.length > 1) {
          rawAttack = row[row.length - 2] || 'Normal';
        }
      }
      if (!rawAttack) {
        rawAttack = (Math.random() < 0.3 ? randomChoice(ATTACK_TEMPLATES).type : 'TLS_ENCRYPTED_STREAM');
      }

      let rawConf = (colConfidence >= 0 && row[colConfidence]) ? parseFloat(row[colConfidence]) : null;
      let rawProto = (colProtocol >= 0 && row[colProtocol]) ? row[colProtocol] : 'TCP (6)';

      // Normalize attack string & map to SOC analyst categories
      let attackType = String(rawAttack).toUpperCase().replace(/[\s-]/g, '_');
      let severity = 'normal';

      if (attackType.includes('NORMAL') || attackType.includes('BENIGN') || attackType.includes('NOMINAL')) {
        attackType = 'TLS_ENCRYPTED_STREAM';
        severity = 'normal';
      } else if (attackType.includes('DOS')) {
        attackType = 'SYN_FLOOD';
        severity = 'malicious';
      } else if (attackType.includes('PORT') || attackType.includes('SCAN')) {
        attackType = 'PORT_SCAN';
        severity = 'suspicious';
      } else if (attackType.includes('BRUTE')) {
        attackType = 'SSH_BRUTE_FORCE';
        severity = 'malicious';
      } else if (attackType.includes('WEB')) {
        attackType = 'ABNORMAL_TCP_FLAGS';
        severity = 'malicious';
      } else if (attackType.includes('TUNNEL') || attackType.includes('DNS')) {
        attackType = 'DNS_TUNNELING';
        severity = 'suspicious';
      } else if (attackType.includes('EXFIL') || attackType.includes('ICMP')) {
        attackType = 'ICMP_EXFILTRATION';
        severity = 'malicious';
      } else {
        let matchingAttackTemplate = ATTACK_TEMPLATES.find(t => t.type === attackType);
        if (matchingAttackTemplate) {
          severity = matchingAttackTemplate.severity;
        } else if (attackType.includes('SYN') || attackType.includes('FLOOD') || attackType.includes('BOTNET') || attackType.includes('INTRUSION')) {
          severity = 'malicious';
        } else {
          severity = 'suspicious';
        }
      }

      // Detect TCP Flags from record
      let detectedFlags = [];
      if (colSynFlag >= 0 && row[colSynFlag] && parseInt(row[colSynFlag], 10) > 0) detectedFlags.push('SYN');
      if (colAckFlag >= 0 && row[colAckFlag] && parseInt(row[colAckFlag], 10) > 0) detectedFlags.push('ACK');
      if (colFinFlag >= 0 && row[colFinFlag] && parseInt(row[colFinFlag], 10) > 0) detectedFlags.push('FIN');
      if (colPshFlag >= 0 && row[colPshFlag] && parseInt(row[colPshFlag], 10) > 0) detectedFlags.push('PSH');
      if (colRstFlag >= 0 && row[colRstFlag] && parseInt(row[colRstFlag], 10) > 0) detectedFlags.push('RST');
      if (colUrgFlag >= 0 && row[colUrgFlag] && parseInt(row[colUrgFlag], 10) > 0) detectedFlags.push('URG');
      if (detectedFlags.length === 0) {
        detectedFlags = severity === 'malicious' ? ['SYN'] : ['ACK', 'PSH'];
      }

      // Duration & Packet Size
      let durationMs = 120;
      if (colDuration >= 0 && row[colDuration]) {
        let d = parseFloat(row[colDuration]);
        if (!isNaN(d) && d > 0) {
          durationMs = d > 10000 ? Math.round(d / 1000) : Math.round(d);
        }
      }
      let packetSize = 512;
      if (colPacketLen >= 0 && row[colPacketLen]) {
        let s = parseFloat(row[colPacketLen]);
        if (!isNaN(s) && s > 0) {
          packetSize = Math.round(s);
        }
      }

      let confidenceVal = !isNaN(rawConf) && rawConf > 0 
        ? (rawConf <= 1.0 ? +(rawConf * 100).toFixed(1) : +rawConf.toFixed(1))
        : (severity === 'normal' ? 98.4 : severity === 'suspicious' ? 91.5 : 98.7);

      const flowId = 'FK-' + Math.floor(1000000 + Math.random() * 9000000);
      const entropy = severity === 'malicious' ? +(7.2 + Math.random() * 0.7).toFixed(2) : +(3.5 + Math.random() * 2.0).toFixed(2);
      const asymmetry = severity === 'malicious' ? +(0.85 + Math.random() * 0.12).toFixed(2) : +(0.15 + Math.random() * 0.35).toFixed(2);

      parsedRecords.push({
        id: flowId,
        timestamp: rawTimestamp.length > 8 ? rawTimestamp : (rawTimestamp + '.000'),
        date: new Date(),
        srcIp: srcWithPort,
        rawSrcIp: srcWithPort.split(':')[0],
        srcPort: parseInt(srcWithPort.split(':')[1], 10) || 443,
        srcTag: severity === 'malicious' ? 'EXTERNAL ATTACKER' : 'INTERNAL NODE',
        dstIp: dstWithPort,
        rawDstIp: dstWithPort.split(':')[0],
        dstPort: parseInt(dstWithPort.split(':')[1], 10) || dstPortNum,
        dstTag: dstPortNum === 53 ? 'DNS RESOLVER' : dstPortNum === 80 || dstPortNum === 443 ? 'WEB SERVICE' : 'PROTECTED ENDPOINT',
        attackType: attackType,
        severity: severity,
        confidence: confidenceVal,
        protocol: dstPortNum === 53 ? 'UDP (17)' : rawProto.toUpperCase().includes('UDP') ? 'UDP (17)' : 'TCP (6)',
        durationMs: durationMs,
        packetSize: packetSize,
        ttl: randomInt(50, 128),
        geo: severity === 'malicious' ? 'AS49505 (MALICIOUS SINKHOLE)' : 'AS15169 (ENTERPRISE CORE)',
        tcpFlags: detectedFlags,
        windowSize: randomInt(2048, 65535),
        seq: '0x' + Math.floor(Math.random() * 0xFFFFFFFF).toString(16).toUpperCase(),
        ack: '0x' + Math.floor(Math.random() * 0xFFFFFFFF).toString(16).toUpperCase(),
        entropy: entropy,
        asymmetry: asymmetry,
        desc: 'Ingested Traffic Record: Class [' + attackType + '] Severity [' + severity.toUpperCase() + ']. Confidence ' + confidenceVal + '%.',
        rawHex: generateHexSample(attackType, Math.min(packetSize, 512)),
        isQuarantined: false
      });
    }

    return parsedRecords;
  }

  // Embedded Sample Dataset fallback for offline / file:// local runs
  const EMBEDDED_SAMPLE_CSV = "Destination Port,Flow Duration,Total Fwd Packets,Total Backward Packets,Total Length of Fwd Packets,Total Length of Bwd Packets,Fwd Packet Length Max,Fwd Packet Length Min,Fwd Packet Length Mean,Fwd Packet Length Std,Bwd Packet Length Max,Bwd Packet Length Min,Bwd Packet Length Mean,Bwd Packet Length Std,Flow Bytes/s,Flow Packets/s,Flow IAT Mean,Flow IAT Std,Flow IAT Max,Flow IAT Min,Fwd IAT Total,Fwd IAT Mean,Fwd IAT Std,Fwd IAT Max,Fwd IAT Min,Bwd IAT Total,Bwd IAT Mean,Bwd IAT Std,Bwd IAT Max,Bwd IAT Min,Fwd PSH Flags,Fwd URG Flags,Fwd Header Length,Bwd Header Length,Fwd Packets/s,Bwd Packets/s,Min Packet Length,Max Packet Length,Packet Length Mean,Packet Length Std,Packet Length Variance,FIN Flag Count,SYN Flag Count,RST Flag Count,PSH Flag Count,ACK Flag Count,URG Flag Count,CWE Flag Count,ECE Flag Count,Down/Up Ratio,Average Packet Size,Avg Fwd Segment Size,Avg Bwd Segment Size,Fwd Header Length.1,Subflow Fwd Packets,Subflow Fwd Bytes,Subflow Bwd Packets,Subflow Bwd Bytes,Init_Win_bytes_forward,Init_Win_bytes_backward,act_data_pkt_fwd,min_seg_size_forward,Active Mean,Active Std,Active Max,Active Min,Idle Mean,Idle Std,Idle Max,Idle Min,Label,flow_missing\n53,30663,1,1,51,112,51,51,51.0,0.0,112,112,112.0,0.0,5315.852982,65.22518997,30663.0,0.0,30663,30663,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,20,20,32.61259498,32.61259498,51,112,71.33333333,35.21836642,1240.333333,0,0,0,0,0,0,0,0,1,107.0,51.0,112.0,20,1,51,1,112,-1,-1,0,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n80,4066350,2,0,0,0,0,0,0.0,0.0,0,0,0.0,0.0,0.0,0.491841578,4066350.0,0.0,4066350,4066350,4066350,4066350.0,0.0,4066350,4066350,0,0.0,0.0,0,0,0,0,64,0,0.491841578,0.0,0,0,0.0,0.0,0.0,0,0,0,0,1,0,0,0,0,0.0,0.0,0.0,64,2,0,0,0,284,-1,0,32,0.0,0.0,0,0,0.0,0.0,0,0,DoS,0\n80,69824715,15,14,3645,907,1576,0,243.0,540.6386435,308,0,64.78571429,128.795711,65.19181639,0.41532572,2493739.821,4095345.238,10000000,21,65500000,4682019.429,4916653.467,10100000,130,69700000,5362186.846,4707738.478,10100000,552,0,0,488,456,0.214823648,0.200502072,0,1576,151.7333333,396.6026356,157293.6506,0,0,0,1,0,0,0,0,0,156.9655172,243.0,64.78571429,488,15,3645,14,907,29200,297,3,32,900975.0,1922464.389,4825189,116060,9925088.167,239895.7046,10000000,9435804,Normal,0\n53,283,2,2,72,454,36,36,36.0,0.0,227,227,227.0,0.0,1858657.244,14134.27562,94.33333333,160.7928274,280,1,1,1.0,0.0,1,1,2,2.0,0.0,2,2,0,0,40,40,7067.137809,7067.137809,36,227,112.4,104.6150085,10944.3,0,0,0,0,0,0,0,0,1,140.5,36.0,227.0,40,2,72,2,454,-1,-1,1,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n42814,42,1,1,0,0,0,0,0.0,0.0,0,0,0.0,0.0,0.0,47619.04762,42.0,0.0,42,42,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,32,32,23809.52381,23809.52381,0,0,0.0,0.0,0.0,0,0,0,0,1,1,0,0,1,0.0,0.0,0.0,32,1,0,1,0,126,245,0,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n53,126743,4,2,144,292,36,36,36.0,0.0,146,146,146.0,0.0,3440.0321911269,47.3398925384,25348.6,41358.3928459509,95180,2,31559,10519.6666666667,18215.401020382,31553,2,4,4.0,0.0,4,4,0,0,104,40,31.559928359,15.7799641795,36,146,67.4285714286,53.6745040122,2880.9523809524,0,0,0,0,0,0,0,0,0,78.6666666667,36.0,146.0,104,4,144,2,292,-1,-1,3,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n53,71665,2,2,72,340,36,36,36.0,0.0,170,170,170.0,0.0,5748.9709063002,55.8152515175,23888.3333333333,41370.6108890518,71659,3,3,3.0,0.0,3,3,3,3.0,0.0,3,3,0,0,40,64,27.9076257587,27.9076257587,36,170,89.6,73.3948227057,5386.8,0,0,0,0,0,0,0,0,1,112.0,36.0,170.0,40,2,72,2,340,-1,-1,1,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n53,43369,2,2,80,112,40,40,40.0,0.0,56,56,56.0,0.0,4427.125366,92.23177846,14456.33333,24994.08109,43317,3,3,3.0,0.0,3,3,49,49.0,0.0,49,49,0,0,64,64,46.11588923,46.11588923,40,56,46.4,8.76356092,76.8,0,0,0,0,0,0,0,0,1,58.0,40.0,56.0,64,2,80,2,112,-1,-1,1,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n58658,57,1,1,0,0,0,0,0.0,0.0,0,0,0.0,0.0,0.0,35087.7193,57.0,0.0,57,57,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,32,32,17543.85965,17543.85965,0,0,0.0,0.0,0.0,0,0,0,0,1,1,0,0,1,0.0,0.0,0.0,32,1,0,1,0,349,316,0,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n62913,103100,2,1,6,6,6,0,3.0,4.2426406871,6,6,6.0,0.0,116.3918525703,29.0979631426,51550.0,72754.2167162839,102995,105,103100,103100.0,0.0,103100,103100,0,0.0,0.0,0,0,0,0,52,20,19.3986420951,9.6993210475,0,6,4.5,3.0,9.0,0,0,0,0,1,1,0,0,0,6.0,3.0,6.0,52,2,6,1,6,10231,32850,0,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n49563,5,3,0,0,0,0,0,0.0,0.0,0,0,0.0,0.0,0.0,600000.0,2.5,2.121320344,4,1,5,2.5,2.121320344,4,1,0,0.0,0.0,0,0,0,0,96,0,600000.0,0.0,0,0,0.0,0.0,0.0,0,0,0,0,1,0,0,0,0,0.0,0.0,0.0,96,3,0,0,0,395,-1,0,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n80,11121118,7,5,321,11632,321,0,45.85714286,121.3265958,8736,0,2326.4,3796.176603,1074.802012,1.079028206,1011010.727,2262094.46,6118056,49,6122752,1020458.667,2499051.416,6121626,49,11100000,2780267.25,3242058.527,6118056,196,0,0,232,168,0.62943312,0.449595086,0,8736,919.4615385,2480.208816,6151435.769,0,0,0,1,0,0,0,0,0,996.0833333,45.85714286,2326.4,232,7,321,5,11632,29200,235,1,32,690.0,0.0,690,690,6118056.0,0.0,6118056,6118056,DoS,0\n443,118274409,16,15,856,4720,234,0,53.5,77.48978427,1460,0,314.6666667,533.5829922,47.14460251,0.262102345,3942480.3,14900000.0,58900000,4,118000000,7884960.6,20700000.0,59000000,4,118000000,8447093.714,21400000.0,58900000,49,0,0,356,312,0.13527863,0.126823716,0,1460,174.25,386.6909243,149529.871,0,0,0,1,0,0,0,0,0,179.8709677,53.5,314.6666667,356,16,856,15,4720,8192,32,13,20,169881.0,78299.34809,225247,114515,58900000.0,101800.7491,58900000,58800000,Normal,0\n53,30680,2,2,68,158,34,34,34.0,0.0,79,79,79.0,0.0,7366.3624511082,130.3780964798,10226.6666666667,17629.9678199744,30584,48,48,48.0,0.0,48,48,48,48.0,0.0,48,48,0,0,64,40,65.1890482399,65.1890482399,34,79,52.0,24.6475150877,607.5,0,0,0,0,0,0,0,0,1,65.0,34.0,79.0,64,2,68,2,158,-1,-1,1,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n39961,71,1,1,0,0,0,0,0.0,0.0,0,0,0.0,0.0,0.0,28169.014084507,71.0,0.0,71,71,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,32,32,14084.5070422535,14084.5070422535,0,0,0.0,0.0,0.0,0,0,0,0,1,1,0,0,1,0.0,0.0,0.0,32,1,0,1,0,132,338,0,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n80,100897613,7,7,1002,11595,330,0,143.1428571,174.8060149,4344,0,1656.428571,1760.597234,124.8493361,0.138754521,7761354.846,27800000.0,100000000,5,101000000,16800000.0,40900000.0,100000000,1011,101000000,16800000.0,40900000.0,100000000,16,0,0,208,232,0.069377261,0.069377261,0,4344,840.2,1402.606563,1967305.171,1,0,0,0,0,0,0,0,1,900.2142857,143.1428571,1656.428571,208,7,1002,7,11595,0,235,4,20,10985.0,0.0,10985,10985,100000000.0,0.0,100000000,100000000,DoS,0\n53,198,2,2,92,248,46,46,46.0,0.0,124,124,124.0,0.0,1717171.71717172,20202.0202020202,66.0,30.3150127824,101,48,48,48.0,0.0,48,48,49,49.0,0.0,49,49,0,0,64,64,10101.0101010101,10101.0101010101,46,124,77.2,42.7223594854,1825.2,0,0,0,0,0,0,0,0,1,96.5,46.0,124.0,64,2,92,2,248,-1,-1,1,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n53,243,2,2,84,192,42,42,42.0,0.0,96,96,96.0,0.0,1135802.469,16460.90535,81.0,98.72689603,192,3,48,48.0,0.0,48,48,3,3.0,0.0,3,3,0,0,64,64,8230.452675,8230.452675,42,96,63.6,29.57701811,874.8,0,0,0,0,0,0,0,0,1,79.5,42.0,96.0,64,2,84,2,192,-1,-1,1,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n57736,52,1,1,0,0,0,0,0.0,0.0,0,0,0.0,0.0,0.0,38461.5384615385,52.0,0.0,52,52,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,32,32,19230.7692307692,19230.7692307692,0,0,0.0,0.0,0.0,0,0,0,0,1,0,0,0,1,0.0,0.0,0.0,32,1,0,1,0,122,33304,0,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n80,68093666,6,5,290,11595,290,0,48.33333333,118.3920042,7240,0,2319.0,3331.638186,174.5389946,0.161542191,6809366.6,21500000.0,67900000,3,68000000,13600000.0,30400000.0,67900000,3,165487,41371.75,66959.08916,140263,97,0,0,200,168,0.088113922,0.073428269,0,7240,990.4166667,2327.719425,5418277.72,0,0,0,0,1,0,0,0,0,1080.454545,48.33333333,2319.0,200,6,290,5,11595,251,235,1,32,995.0,0.0,995,995,67900000.0,0.0,67900000,67900000,DoS,0\n80,99797578,8,6,423,11595,417,0,52.875,147.143698,4344,0,1932.5,1754.831473,120.4237642,0.140283966,7676736.769,27600000.0,99600000,2,99700000,14200000.0,37700000.0,99600000,3,147440,29488.0,59328.83994,135219,15,0,0,252,200,0.080162266,0.0601217,0,4344,801.2,1423.015119,2024972.029,0,0,0,0,1,0,0,0,0,858.4285714,52.875,1932.5,252,8,423,6,11595,251,235,2,20,2955.0,0.0,2955,2955,99600000.0,0.0,99600000,99600000,DoS,0\n443,15210056,9,8,1332,3542,773,0,148.0,265.6233235,1400,0,442.75,608.0142738,320.4458945,1.117681618,950628.5,2714177.077,9959910,2,10100000,1263807.25,3513824.999,9959910,3,15200000,2169360.0,3941891.121,10000000,2,0,0,296,264,0.591713798,0.52596782,0,1400,270.7777778,460.0384326,211635.3595,0,0,0,1,0,0,0,0,0,286.7058824,148.0,442.75,296,9,1332,8,3542,29200,13914,3,32,87558.0,89081.31229,150548,24568,7517470.0,3454131.773,9959910,5075030,Normal,0\n53,30658,1,1,81,159,81,81,81.0,0.0,159,159,159.0,0.0,7828.299302,65.23582752,30658.0,0.0,30658,30658,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,32,32,32.61791376,32.61791376,81,159,107.0,45.033321,2028.0,0,0,0,0,0,0,0,0,1,160.5,81.0,159.0,32,1,81,1,159,-1,-1,0,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n443,5257788,9,11,1502,7228,974,0,166.8888889,326.3803167,1448,0,657.0909091,676.0792046,1660.394067,3.803881024,276725.6842,1143011.698,4995474,4,262310,32788.75,37608.33356,99562,176,5206169,520616.9,1572657.597,4995503,4,0,0,296,360,1.711746461,2.092134563,0,1448,415.7142857,582.8360956,339697.9143,0,0,0,1,0,0,0,0,1,436.5,166.8888889,657.0909091,296,9,1502,11,7228,29200,19,3,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n1322,57,1,1,0,6,0,0,0.0,0.0,6,6,6.0,0.0,105263.1579,35087.7193,57.0,0.0,57,57,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,40,20,17543.85965,17543.85965,0,6,2.0,3.464101615,12.0,0,0,0,1,0,0,0,0,1,3.0,0.0,6.0,40,1,0,1,6,29200,0,0,40,0.0,0.0,0,0,0.0,0.0,0,0,PortScan,0\n80,99998,1,1,0,0,0,0,0.0,0.0,0,0,0.0,0.0,0.0,20.00040001,99998.0,0.0,99998,99998,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,32,32,10.0002,10.0002,0,0,0.0,0.0,0.0,0,0,0,0,1,1,0,0,1,0.0,0.0,0.0,32,1,0,1,0,237,110,0,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n60223,31,1,1,0,0,0,0,0.0,0.0,0,0,0.0,0.0,0.0,64516.12903,31.0,0.0,31,31,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,32,32,32258.06452,32258.06452,0,0,0.0,0.0,0.0,0,0,0,0,1,1,0,0,1,0.0,0.0,0.0,32,1,0,1,0,411,339,0,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n53,334,2,2,66,176,33,33,33.0,0.0,88,88,88.0,0.0,724550.8982,11976.0479,111.3333333,189.3735286,330,1,1,1.0,0.0,1,1,3,3.0,0.0,3,3,0,0,64,64,5988.023952,5988.023952,33,88,55.0,30.12474066,907.5,0,0,0,0,0,0,0,0,1,68.75,33.0,88.0,64,2,66,2,176,-1,-1,1,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n5862,29,1,1,0,6,0,0,0.0,0.0,6,6,6.0,0.0,206896.5517,68965.51724,29.0,0.0,29,29,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,40,20,34482.75862,34482.75862,0,6,2.0,3.464101615,12.0,0,0,0,1,0,0,0,0,1,3.0,0.0,6.0,40,1,0,1,6,29200,0,0,40,0.0,0.0,0,0,0.0,0.0,0,0,PortScan,0\n53,184,2,2,72,208,36,36,36.0,0.0,104,104,104.0,0.0,1521739.13,21739.13043,61.33333333,67.98774399,135,1,1,1.0,0.0,1,1,48,48.0,0.0,48,48,0,0,64,64,10869.56522,10869.56522,36,104,63.2,37.24513391,1387.2,0,0,0,0,0,0,0,0,1,79.0,36.0,104.0,64,2,72,2,208,-1,-1,1,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n80,98815269,7,6,381,11595,357,0,54.42857143,133.4514358,8688,0,1932.5,3506.021777,121.1958447,0.131558616,8234605.75,28500000.0,98800000,14,98800000,16500000.0,40300000.0,98800000,68,98800000,19800000.0,44200000.0,98800000,179,0,0,184,200,0.070839255,0.060719361,0,8688,855.8571429,2381.677329,5672386.901,1,0,0,0,0,0,0,0,0,921.6923077,54.42857143,1932.5,184,7,381,6,11595,0,235,4,20,19182.0,0.0,19182,19182,98800000.0,0.0,98800000,98800000,DoS,0\n84,25,1,1,2,6,2,2,2.0,0.0,6,6,6.0,0.0,320000.0,80000.0,25.0,0.0,25,25,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,24,20,40000.0,40000.0,2,6,3.333333333,2.309401077,5.333333333,0,0,0,1,0,0,0,0,1,5.0,2.0,6.0,24,1,2,1,6,1024,0,0,24,0.0,0.0,0,0,0.0,0.0,0,0,PortScan,0\n53,255,2,2,70,102,35,35,35.0,0.0,51,51,51.0,0.0,674509.803921569,15686.2745098039,85.0,62.3538290725,157,49,49,49.0,0.0,49,49,49,49.0,0.0,49,49,0,0,40,40,7843.137254902,7843.137254902,35,51,41.4,8.7635609201,76.8,0,0,0,0,0,0,0,0,1,51.75,35.0,51.0,40,2,70,2,102,-1,-1,1,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n80,22184,1,1,0,0,0,0,0.0,0.0,0,0,0.0,0.0,0.0,90.1550667147,22184.0,0.0,22184,22184,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,32,32,45.0775333574,45.0775333574,0,0,0.0,0.0,0.0,0,0,0,0,1,1,0,0,1,0.0,0.0,0.0,32,1,0,1,0,552,131,0,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n80,1261312,3,4,26,11601,20,0,8.666666667,10.26320288,8760,0,2900.25,4128.319301,9218.179166,5.54977674,210218.6667,499089.1223,1228656,9,32281,16140.5,22141.63464,31797,484,1261219,420406.3333,700145.6605,1228656,366,0,0,72,92,2.378475746,3.171300995,0,8760,1453.375,3113.952607,9696700.839,0,0,0,1,0,0,0,0,1,1661.0,8.666666667,2900.25,72,3,26,4,11601,8192,229,2,20,0.0,0.0,0,0,0.0,0.0,0,0,DoS,0\n80,10200010,5,0,30,0,6,6,6.0,0.0,0,0,0.0,0.0,2.941173587,0.490195598,2550002.5,5099167.006,10200000,228,10200000,2550002.5,5099167.006,10200000,228,0,0.0,0.0,0,0,0,0,100,0,0.490195598,0.0,6,6,6.0,0.0,0.0,0,0,0,0,1,0,0,0,0,7.2,6.0,0.0,100,5,30,0,0,256,-1,4,20,1257.0,0.0,1257,1257,10200000.0,0.0,10200000,10200000,DoS,0\n80,11009,3,1,18,0,6,6,6.0,0.0,0,0,0.0,0.0,1635.025888,363.3390862,3669.666667,6331.811773,10981,2,11009,5504.5,7781.710127,11007,2,0,0.0,0.0,0,0,0,0,60,32,272.5043147,90.83477155,0,6,4.8,2.683281573,7.2,1,0,0,0,0,0,0,0,0,6.0,6.0,0.0,60,3,18,1,0,0,235,2,20,0.0,0.0,0,0,0.0,0.0,0,0,DoS,0\n80,11611711,5,4,405,3525,405,0,81.0,181.1215062,3525,0,881.25,1762.5,338.4514134,0.775079573,1451463.875,2720022.249,6606511,9,6611949,1652987.25,3305247.836,6610859,231,11600000,3870567.333,3445702.602,6606511,831,0,0,168,136,0.430599763,0.34447981,0,3525,393.0,1107.808648,1227240.0,0,0,0,1,0,0,0,0,0,436.6666667,81.0,881.25,168,5,405,4,3525,29200,235,1,32,840.0,0.0,840,840,6606511.0,0.0,6606511,6606511,DoS,0\n53,174,2,2,76,154,38,38,38.0,0.0,77,77,77.0,0.0,1321839.08,22988.50575,58.0,60.25777958,123,4,4,4.0,0.0,4,4,47,47.0,0.0,47,47,0,0,40,40,11494.25287,11494.25287,38,77,53.6,21.36117974,456.3,0,0,0,0,0,0,0,0,1,67.0,38.0,77.0,40,2,76,2,154,-1,-1,1,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n80,10994,3,1,18,0,6,6,6.0,0.0,0,0,0.0,0.0,1637.256685,363.834819,3664.666667,6346.522854,10993,0,10994,5497.0,7773.931952,10994,0,0,0.0,0.0,0,0,0,0,60,32,272.8761142,90.95870475,0,6,4.8,2.683281573,7.2,1,0,0,0,0,0,0,0,0,6.0,6.0,0.0,60,3,18,1,0,0,235,2,20,0.0,0.0,0,0,0.0,0.0,0,0,DoS,0\n53,23817,2,2,94,262,47,47,47.0,0.0,131,131,131.0,0.0,14947.3065457446,167.9472645589,7939.0,13705.7373387936,23765,3,3,3.0,0.0,3,3,49,49.0,0.0,49,49,0,0,40,40,83.9736322795,83.9736322795,47,131,80.6,46.0086948304,2116.8,0,0,0,0,0,0,0,0,1,100.75,47.0,131.0,40,2,94,2,262,-1,-1,1,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n46130,48,1,1,0,0,0,0,0.0,0.0,0,0,0.0,0.0,0.0,41666.6666666667,48.0,0.0,48,48,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,32,32,20833.3333333333,20833.3333333333,0,0,0.0,0.0,0.0,0,0,0,0,1,1,0,0,1,0.0,0.0,0.0,32,1,0,1,0,122,360,0,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n53,30324,1,1,44,72,44,44,44.0,0.0,72,72,72.0,0.0,3825.3528558238,65.9543595832,30324.0,0.0,30324,30324,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,20,20,32.9771797916,32.9771797916,44,72,53.3333333333,16.1658075373,261.3333333333,0,0,0,0,0,0,0,0,1,80.0,44.0,72.0,20,1,44,1,72,-1,-1,0,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n43744,83,1,1,0,0,0,0,0.0,0.0,0,0,0.0,0.0,0.0,24096.38554,83.0,0.0,83,83,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,32,32,12048.19277,12048.19277,0,0,0.0,0.0,0.0,0,0,0,0,1,1,0,0,1,0.0,0.0,0.0,32,1,0,1,0,939,256,0,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n33409,60,1,2,0,0,0,0,0.0,0.0,0,0,0.0,0.0,0.0,50000.0,30.0,26.8700576851,49,11,0,0.0,0.0,0,0,49,49.0,0.0,49,49,0,0,32,64,16666.6666666667,33333.3333333333,0,0,0.0,0.0,0.0,0,0,0,0,1,1,0,0,2,0.0,0.0,0.0,32,1,0,2,0,243,290,0,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n51862,11,1,1,0,0,0,0,0.0,0.0,0,0,0.0,0.0,0.0,181818.1818,11.0,0.0,11,11,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,32,32,90909.09091,90909.09091,0,0,0.0,0.0,0.0,0,0,0,0,1,1,0,0,1,0.0,0.0,0.0,32,1,0,1,0,349,65535,0,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n53,198,2,2,154,250,77,77,77.0,0.0,125,125,125.0,0.0,2040404.04040404,20202.0202020202,66.0,108.2543301674,191,3,4,4.0,0.0,4,4,3,3.0,0.0,3,3,0,0,40,40,10101.0101010101,10101.0101010101,77,125,96.2,26.2906827602,691.2,0,0,0,0,0,0,0,0,1,120.25,77.0,125.0,40,2,154,2,250,-1,-1,1,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n53,270,2,2,64,290,32,32,32.0,0.0,145,145,145.0,0.0,1311111.111,14814.81481,90.0,154.1525219,268,1,1,1.0,0.0,1,1,1,1.0,0.0,1,1,0,0,64,64,7407.407407,7407.407407,32,145,77.2,61.892649,3830.7,0,0,0,0,0,0,0,0,1,96.5,32.0,145.0,64,2,64,2,290,-1,-1,1,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n8565,4,2,0,37,0,31,6,18.5,17.67766953,0,0,0.0,0.0,9250000.0,500000.0,4.0,0.0,4,4,4,4.0,0.0,4,4,0,0.0,0.0,0,0,1,0,40,0,500000.0,0.0,6,31,22.66666667,14.43375673,208.3333333,0,1,0,0,1,0,0,0,0,34.0,18.5,0.0,40,2,37,0,0,16616,-1,1,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n80,1126,6,0,0,0,0,0,0.0,0.0,0,0,0.0,0.0,0.0,5328.596803,225.2,228.3006789,484,3,1126,225.2,228.3006789,484,3,0,0.0,0.0,0,0,0,0,192,0,5328.596803,0.0,0,0,0.0,0.0,0.0,0,0,0,0,1,0,0,0,0,0.0,0.0,0.0,192,6,0,0,0,251,-1,0,32,0.0,0.0,0,0,0.0,0.0,0,0,DoS,0\n53,23685,1,1,46,62,46,46,46.0,0.0,62,62,62.0,0.0,4559.8480050665,84.4416297235,23685.0,0.0,23685,23685,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,20,20,42.2208148617,42.2208148617,46,62,51.3333333333,9.237604307,85.3333333333,0,0,0,0,0,0,0,0,1,77.0,46.0,62.0,20,1,46,1,62,-1,-1,0,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n80,8184512,5,0,30,0,6,6,6.0,0.0,0,0,0.0,0.0,3.665459834,0.610909972,2046128.0,4091470.001,8183333,330,8184512,2046128.0,4091470.001,8183333,330,0,0.0,0.0,0,0,0,0,100,0,0.610909972,0.0,6,6,6.0,0.0,0.0,0,0,0,0,1,0,0,0,0,7.2,6.0,0.0,100,5,30,0,0,256,-1,4,20,1179.0,0.0,1179,1179,8183333.0,0.0,8183333,8183333,DoS,0\n64608,18,1,1,6,6,6,6,6.0,0.0,6,6,6.0,0.0,666666.666666667,111111.111111111,18.0,0.0,18,18,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,20,20,55555.5555555556,55555.5555555556,6,6,6.0,0.0,0.0,0,0,1,1,0,0,1,9.0,6.0,6.0,20,1,6,1,6,58,256,0,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n61123,4,1,1,6,6,6,6,6.0,0.0,6,6,6.0,0.0,3000000.0,500000.0,4.0,0.0,4,4,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,20,20,250000.0,250000.0,6,6,6.0,0.0,0.0,0,0,0,0,1,1,0,0,1,9.0,6.0,6.0,20,1,6,1,6,33580,63916,0,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n53,204,2,2,102,306,51,51,51.0,0.0,153,153,153.0,0.0,2000000.0,19607.84314,68.0,76.97402159,153,3,3,3.0,0.0,3,3,48,48.0,0.0,48,48,0,0,40,40,9803.921569,9803.921569,51,153,91.8,55.86770087,3121.2,0,0,0,0,0,0,0,0,1,114.75,51.0,153.0,40,2,102,2,306,-1,-1,1,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n80,16232,1,1,6,6,6,6,6.0,0.0,6,6,6.0,0.0,739.2804337,123.2134056,16232.0,0.0,16232,16232,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,20,20,61.60670281,61.60670281,6,6,6.0,0.0,0.0,0,0,0,0,1,1,0,0,1,9.0,6.0,6.0,20,1,6,1,6,239,244,0,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n80,11174655,6,4,265,3525,265,0,44.16666667,108.185797,3525,0,881.25,1762.5,339.1603589,0.894882213,1241628.333,2203550.235,5170693,49,6175814,1235162.8,2244398.567,5175142,716,10200000,3392283.333,2937234.98,5170693,2020,0,0,208,136,0.536929328,0.357952885,0,3525,344.5454545,1057.829038,1119002.273,0,0,0,1,0,0,0,0,0,379.0,44.16666667,881.25,208,6,265,4,3525,29200,235,1,32,999825.0,0.0,999825,999825,5170693.0,0.0,5170693,5170693,DoS,0\n80,22005,2,1,12,0,6,6,6.0,0.0,0,0,0.0,0.0,545.3306067,136.3326517,11002.5,15521.70095,21978,27,22005,22005.0,0.0,22005,22005,0,0.0,0.0,0,0,0,0,40,32,90.88843445,45.44421722,0,6,4.5,3.0,9.0,1,0,0,0,0,0,0,0,0,6.0,6.0,0.0,40,2,12,1,0,0,235,1,20,0.0,0.0,0,0,0.0,0.0,0,0,DoS,0\n80,29910212,7,7,3259,727,2920,0,465.5714286,1088.460052,697,0,103.8571429,261.5609735,133.2655215,0.468067562,2300785.538,4236981.018,10000000,31,20400000,3407314.0,5017575.576,10000000,23187,29900000,4981189.5,5318081.345,10000000,1300,0,0,152,148,0.234033781,0.234033781,0,2920,265.7333333,758.4073977,575181.781,0,0,0,1,0,0,0,0,1,284.7142857,465.5714286,103.8571429,152,7,3259,7,727,8192,7615,6,20,242208.6667,379592.2139,680524,23035,9727862.0,278788.2153,10000000,9443261,Normal,0\n22662,11,1,1,6,6,6,6,6.0,0.0,6,6,6.0,0.0,1090909.091,181818.1818,11.0,0.0,11,11,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,20,20,90909.09091,90909.09091,6,6,6.0,0.0,0.0,0,0,0,0,1,1,0,0,1,9.0,6.0,6.0,20,1,6,1,6,119,255,0,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n53,23690,2,2,130,284,65,65,65.0,0.0,142,142,142.0,0.0,17475.72816,168.847615,7896.666667,13633.27915,23639,3,3,3.0,0.0,3,3,48,48.0,0.0,48,48,0,0,40,64,84.42380751,84.42380751,65,142,95.8,42.17463693,1778.7,0,0,0,0,0,0,0,0,1,119.75,65.0,142.0,40,2,130,2,284,-1,-1,1,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n53,24101,2,2,68,422,34,34,34.0,0.0,211,211,211.0,0.0,20331.1065930874,165.9682170864,8033.6666666667,13909.5226853165,24095,3,3,3.0,0.0,3,3,3,3.0,0.0,3,3,0,0,64,64,82.9841085432,82.9841085432,34,211,104.8,96.9468926784,9398.7,0,0,0,0,0,0,0,0,1,131.0,34.0,211.0,64,2,68,2,422,-1,-1,1,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n53,100363,2,2,58,162,29,29,29.0,0.0,81,81,81.0,0.0,2192.042884,39.85532517,33454.33333,57900.44214,100312,3,3,3.0,0.0,3,3,48,48.0,0.0,48,48,0,0,80,64,19.92766258,19.92766258,29,81,49.8,28.48157299,811.2,0,0,0,0,0,0,0,0,1,62.25,29.0,81.0,80,2,58,2,162,-1,-1,1,40,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n53,46791,2,2,74,444,37,37,37.0,0.0,222,222,222.0,0.0,11070.50501,85.48652519,15597.0,27009.60029,46785,3,3,3.0,0.0,3,3,3,3.0,0.0,3,3,0,0,64,80,42.74326259,42.74326259,37,222,111.0,101.3286731,10267.5,0,0,0,0,0,0,0,0,1,138.75,37.0,222.0,64,2,74,2,444,-1,-1,1,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n58388,104,1,1,0,0,0,0,0.0,0.0,0,0,0.0,0.0,0.0,19230.76923,104.0,0.0,104,104,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,32,32,9615.384615,9615.384615,0,0,0.0,0.0,0.0,0,0,0,0,1,1,0,0,1,0.0,0.0,0.0,32,1,0,1,0,905,229,0,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n80,79034,5,0,30,0,6,6,6.0,0.0,0,0,0.0,0.0,379.5834704,63.26391173,19758.5,38181.89589,77027,4,79034,19758.5,38181.89589,77027,4,0,0.0,0.0,0,0,0,0,100,0,63.26391173,0.0,6,6,6.0,0.0,0.0,0,0,0,0,1,0,0,0,0,7.2,6.0,0.0,100,5,30,0,0,256,-1,4,20,0.0,0.0,0,0,0.0,0.0,0,0,DoS,0\n53,280,2,2,134,390,67,67,67.0,0.0,195,195,195.0,0.0,1871428.571,14285.71429,93.33333333,118.681647,228,4,4,4.0,0.0,4,4,48,48.0,0.0,48,48,0,0,40,40,7142.857143,7142.857143,67,195,118.2,70.10848736,4915.2,0,0,0,0,0,0,0,0,1,147.75,67.0,195.0,40,2,134,2,390,-1,-1,1,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n53,66491,1,1,47,129,47,47,47.0,0.0,129,129,129.0,0.0,2646.974779,30.07925885,66491.0,0.0,66491,66491,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,32,32,15.03962942,15.03962942,47,129,74.33333333,47.34272207,2241.333333,0,0,0,0,0,0,0,0,1,111.5,47.0,129.0,32,1,47,1,129,-1,-1,0,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n53,91101,1,1,49,225,49,49,49.0,0.0,225,225,225.0,0.0,3007.650849,21.95365583,91101.0,0.0,91101,91101,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,20,20,10.97682792,10.97682792,49,225,107.6666667,101.6136474,10325.33333,0,0,0,0,0,0,0,0,1,161.5,49.0,225.0,20,1,49,1,225,-1,-1,0,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n57174,76,1,1,0,0,0,0,0.0,0.0,0,0,0.0,0.0,0.0,26315.78947,76.0,0.0,76,76,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,32,32,13157.89474,13157.89474,0,0,0.0,0.0,0.0,0,0,0,0,1,1,0,0,1,0.0,0.0,0.0,32,1,0,1,0,972,245,0,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n80,1159092,3,5,26,11607,20,0,8.666666667,10.26320288,10135,0,2321.4,4413.201989,10036.30428,6.901954288,165584.5714,437610.1551,1157991,13,824,412.0,343.6538957,655,169,1159078,289769.5,578814.453,1157991,13,0,0,72,112,2.588232858,4.31372143,0,10135,1292.555556,3350.634907,11200000.0,0,0,0,1,0,0,0,0,1,1454.125,8.666666667,2321.4,72,3,26,5,11607,8192,229,2,20,0.0,0.0,0,0,0.0,0.0,0,0,DoS,0\n80,991,4,0,6,0,6,0,1.5,3.0,0,0,0.0,0.0,6054.490414,4036.326942,330.3333333,566.9614919,985,1,991,330.3333333,566.9614919,985,1,0,0.0,0.0,0,0,0,0,116,0,4036.326942,0.0,0,6,1.2,2.683281573,7.2,0,0,0,0,1,0,0,0,0,1.5,1.5,0.0,116,4,6,0,0,251,-1,1,20,0.0,0.0,0,0,0.0,0.0,0,0,DoS,0\n53,117,2,2,70,174,35,35,35.0,0.0,87,87,87.0,0.0,2085470.08547009,34188.0341880342,39.0,34.1174442185,67,1,1,1.0,0.0,1,1,49,49.0,0.0,49,49,0,0,40,40,17094.0170940171,17094.0170940171,35,87,55.8,28.4815729903,811.2,0,0,0,0,0,0,0,0,1,69.75,35.0,87.0,40,2,70,2,174,-1,-1,1,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n56908,63,1,1,0,0,0,0,0.0,0.0,0,0,0.0,0.0,0.0,31746.0317460317,63.0,0.0,63,63,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,32,32,15873.0158730159,15873.0158730159,0,0,0.0,0.0,0.0,0,0,0,0,1,1,0,0,1,0.0,0.0,0.0,32,1,0,1,0,399,422,0,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n52844,208,2,0,12,0,6,6,6.0,0.0,0,0,0.0,0.0,57692.30769,9615.384615,208.0,0.0,208,208,208,208.0,0.0,208,208,0,0.0,0.0,0,0,0,0,40,0,9615.384615,0.0,6,6,6.0,0.0,0.0,0,0,0,0,1,0,0,0,0,9.0,6.0,0.0,40,2,12,0,0,360,-1,1,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n53,169,2,2,70,126,35,35,35.0,0.0,63,63,63.0,0.0,1159763.314,23668.63905,56.33333333,57.3527099,117,3,3,3.0,0.0,3,3,49,49.0,0.0,49,49,0,0,64,64,11834.31953,11834.31953,35,63,46.2,15.33623161,235.2,0,0,0,0,0,0,0,0,1,57.75,35.0,63.0,64,2,70,2,126,-1,-1,1,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n63624,75,1,1,6,6,6,6,6.0,0.0,6,6,6.0,0.0,160000.0,26666.6666666667,75.0,0.0,75,75,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,20,20,13333.3333333333,13333.3333333333,6,6,6.0,0.0,0.0,0,0,0,0,1,1,0,0,1,9.0,6.0,6.0,20,1,6,1,6,267,253,0,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n53,293,2,2,94,452,47,47,47.0,0.0,226,226,226.0,0.0,1863481.229,13651.87713,97.66666667,85.16063253,196,48,48,48.0,0.0,48,48,49,49.0,0.0,49,49,0,0,64,64,6825.938567,6825.938567,47,226,118.6,98.04233779,9612.3,0,0,0,0,0,0,0,0,1,148.25,47.0,226.0,64,2,94,2,452,-1,-1,1,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n53,241,2,2,94,256,47,47,47.0,0.0,128,128,128.0,0.0,1452282.158,16597.51037,80.33333333,100.4805122,193,0,0,0.0,0.0,0,0,48,48.0,0.0,48,48,0,0,80,80,8298.755187,8298.755187,47,128,79.4,44.36552716,1968.3,0,0,0,0,0,0,0,0,1,99.25,47.0,128.0,80,2,94,2,256,-1,-1,1,40,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n58275,25,1,1,6,6,6,6,6.0,0.0,6,6,6.0,0.0,480000.0,80000.0,25.0,0.0,25,25,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,20,20,40000.0,40000.0,6,6,6.0,0.0,0.0,0,0,0,0,1,1,0,0,1,9.0,6.0,6.0,20,1,6,1,6,8192,254,0,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n80,27223,3,6,26,11607,20,0,8.666666667,10.26320288,5840,0,1934.5,2538.919278,427322.4847,330.6027991,3402.875,8671.569465,24796,5,2048,1024.0,1441.08362,2043,5,27208,5441.6,10856.82432,24796,15,0,0,72,132,110.200933,220.4018661,0,5840,1163.3,2138.329153,4572451.567,0,0,0,1,0,0,0,0,2,1292.555556,8.666666667,1934.5,72,3,26,6,11607,8192,229,2,20,0.0,0.0,0,0,0.0,0.0,0,0,DoS,0\n53,182,2,2,86,204,43,43,43.0,0.0,102,102,102.0,0.0,1593406.593,21978.02198,60.66666667,98.14954576,174,4,4,4.0,0.0,4,4,4,4.0,0.0,4,4,0,0,80,80,10989.01099,10989.01099,43,102,66.6,32.31563089,1044.3,0,0,0,0,0,0,0,0,1,83.25,43.0,102.0,80,2,86,2,204,-1,-1,1,40,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n53,233,2,2,68,422,34,34,34.0,0.0,211,211,211.0,0.0,2103004.292,17167.38197,77.66666667,129.3264603,227,3,3,3.0,0.0,3,3,3,3.0,0.0,3,3,0,0,40,40,8583.690987,8583.690987,34,211,104.8,96.94689268,9398.7,0,0,0,0,0,0,0,0,1,131.0,34.0,211.0,40,2,68,2,422,-1,-1,1,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n1152,73,1,1,0,6,0,0,0.0,0.0,6,6,6.0,0.0,82191.78082,27397.26027,73.0,0.0,73,73,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,40,20,13698.63014,13698.63014,0,6,2.0,3.464101615,12.0,0,0,0,1,0,0,0,0,1,3.0,0.0,6.0,40,1,0,1,6,29200,0,0,40,0.0,0.0,0,0,0.0,0.0,0,0,PortScan,0\n53,291,2,2,102,306,51,51,51.0,0.0,153,153,153.0,0.0,1402061.856,13745.70447,97.0,125.6940731,240,4,4,4.0,0.0,4,4,47,47.0,0.0,47,47,0,0,40,40,6872.852234,6872.852234,51,153,91.8,55.86770087,3121.2,0,0,0,0,0,0,0,0,1,114.75,51.0,153.0,40,2,102,2,306,-1,-1,1,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n80,99822014,10,7,382,11595,370,0,38.2,116.6093192,5792,0,1656.428571,2118.227235,119.9835539,0.170303116,6238875.875,24900000.0,99700000,1,99700000,11100000.0,33200000.0,99700000,1,149785,24964.16667,55257.10117,137338,7,0,0,304,232,0.100178303,0.070124812,0,5792,665.3888889,1500.886371,2252659.899,0,0,0,0,1,0,0,0,0,704.5294118,38.2,1656.428571,304,10,382,7,11595,274,235,3,20,1991.0,0.0,1991,1991,99700000.0,0.0,99700000,99700000,DoS,0\n53046,40,1,1,6,6,6,6,6.0,0.0,6,6,6.0,0.0,300000.0,50000.0,40.0,0.0,40,40,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,20,20,25000.0,25000.0,6,6,6.0,0.0,0.0,0,0,0,0,1,1,0,0,1,9.0,6.0,6.0,20,1,6,1,6,513,255,0,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n443,501103,3,1,65,6,53,6,21.66666667,27.13546265,6,6,6.0,0.0,141.6874375,7.982390846,167034.3333,261806.0083,468765,3,501103,250551.5,354329.0867,501100,3,0,0.0,0.0,0,0,0,0,60,20,5.986793134,1.995597711,6,53,15.4,21.01903899,441.8,0,0,0,0,1,0,0,0,0,19.25,21.66666667,6.0,60,3,65,1,6,63154,5895,2,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n443,78948,1,2,0,0,0,0,0.0,0.0,0,0,0.0,0.0,0.0,37.999696,39474.0,52754.40852,76777,2171,0,0.0,0.0,0,0,2171,2171.0,0.0,2171,2171,0,0,32,64,12.66656533,25.33313067,0,0,0.0,0.0,0.0,0,0,0,0,1,1,0,0,2,0.0,0.0,0.0,32,1,0,2,0,294,9,0,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n80,18,4,0,6,0,6,0,1.5,3.0,0,0,0.0,0.0,333333.3333,222222.2222,6.0,4.582575695,10,1,18,6.0,4.582575695,10,1,0,0.0,0.0,0,0,0,0,116,0,222222.2222,0.0,0,6,1.2,2.683281573,7.2,0,0,0,0,1,0,0,0,0,1.5,1.5,0.0,116,4,6,0,0,251,-1,1,20,0.0,0.0,0,0,0.0,0.0,0,0,DoS,0\n53,136945,2,2,84,210,42,42,42.0,0.0,105,105,105.0,0.0,2146.847274,29.20880646,45648.33333,79060.03647,136939,2,2,2.0,0.0,2,2,4,4.0,0.0,4,4,0,0,40,40,14.60440323,14.60440323,42,105,67.2,34.50652112,1190.7,0,0,0,0,0,0,0,0,1,84.0,42.0,105.0,40,2,84,2,210,-1,-1,1,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n57570,36,1,1,0,0,0,0,0.0,0.0,0,0,0.0,0.0,0.0,55555.55556,36.0,0.0,36,36,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,32,32,27777.77778,27777.77778,0,0,0.0,0.0,0.0,0,0,0,0,1,1,0,0,1,0.0,0.0,0.0,32,1,0,1,0,365,1324,0,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n53,60397,2,2,64,226,32,32,32.0,0.0,113,113,113.0,0.0,4801.562992,66.22845506,20132.33333,34865.89408,60392,2,2,2.0,0.0,2,2,3,3.0,0.0,3,3,0,0,64,64,33.11422753,33.11422753,32,113,64.4,44.36552716,1968.3,0,0,0,0,0,0,0,0,1,80.5,32.0,113.0,64,2,64,2,226,-1,-1,1,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n53,248,2,2,62,318,31,31,31.0,0.0,159,159,159.0,0.0,1532258.06451613,16129.0322580645,82.6666666667,60.0444279957,152,48,48,48.0,0.0,48,48,48,48.0,0.0,48,48,0,0,64,64,8064.5161290323,8064.5161290323,31,159,82.2,70.1084873607,4915.2,0,0,0,0,0,0,0,0,1,102.75,31.0,159.0,64,2,62,2,318,-1,-1,1,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n56196,80,1,1,0,0,0,0,0.0,0.0,0,0,0.0,0.0,0.0,25000.0,80.0,0.0,80,80,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,32,32,12500.0,12500.0,0,0,0.0,0.0,0.0,0,0,0,0,1,1,0,0,1,0.0,0.0,0.0,32,1,0,1,0,360,1723,0,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n53,237,2,2,94,196,47,47,47.0,0.0,98,98,98.0,0.0,1223628.692,16877.63713,79.0,52.82991577,140,48,48,48.0,0.0,48,48,49,49.0,0.0,49,49,0,0,64,64,8438.818565,8438.818565,47,98,67.4,27.93385043,780.3,0,0,0,0,0,0,0,0,1,84.25,47.0,98.0,64,2,94,2,196,-1,-1,1,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n683,55,1,1,0,6,0,0,0.0,0.0,6,6,6.0,0.0,109090.9091,36363.63636,55.0,0.0,55,55,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,40,20,18181.81818,18181.81818,0,6,2.0,3.464101615,12.0,0,0,0,1,0,0,0,0,1,3.0,0.0,6.0,40,1,0,1,6,29200,0,0,40,0.0,0.0,0,0,0.0,0.0,0,0,PortScan,0\n55888,77,1,1,6,6,6,6,6.0,0.0,6,6,6.0,0.0,155844.155844156,25974.025974026,77.0,0.0,77,77,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,20,20,12987.012987013,12987.012987013,6,6,6.0,0.0,0.0,0,0,0,0,1,1,0,0,1,9.0,6.0,6.0,20,1,6,1,6,119,251,0,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n56518,53,1,2,0,0,0,0,0.0,0.0,0,0,0.0,0.0,0.0,56603.77358,26.5,30.40559159,48,5,0,0.0,0.0,0,0,48,48.0,0.0,48,48,0,0,20,40,18867.92453,37735.84906,0,0,0.0,0.0,0.0,0,0,0,0,1,1,0,0,2,0.0,0.0,0.0,20,1,0,2,0,245,256,0,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n53,24016,2,2,62,162,31,31,31.0,0.0,81,81,81.0,0.0,9327.1152564957,166.5556295803,8005.3333333333,13860.4479124353,24010,3,3,3.0,0.0,3,3,3,3.0,0.0,3,3,0,0,64,40,83.2778147901,83.2778147901,31,81,51.0,27.3861278753,750.0,0,0,0,0,0,0,0,0,1,63.75,31.0,81.0,64,2,62,2,162,-1,-1,1,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n443,136077,12,9,538,5160,201,0,44.83333333,77.17610715,1448,0,573.3333333,631.630232,41873.35112,154.3243899,6803.85,11741.94348,42129,7,136077,12370.63636,19775.43105,65546,17,110960,13870.0,19611.27431,47530,48,0,0,404,296,88.18536564,66.13902423,0,1448,259.0,476.2907275,226852.8571,0,0,0,1,0,0,0,0,0,271.3333333,44.83333333,573.3333333,404,12,538,9,5160,29200,972,4,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n59821,15,1,1,6,6,6,6,6.0,0.0,6,6,6.0,0.0,800000.0,133333.3333,15.0,0.0,15,15,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,20,20,66666.66667,66666.66667,6,6,6.0,0.0,0.0,0,0,0,0,1,1,0,0,1,9.0,6.0,6.0,20,1,6,1,6,119,255,0,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n80,223542,1,1,6,6,6,6,6.0,0.0,6,6,6.0,0.0,53.68118743,8.946864571,223542.0,0.0,223542,223542,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,20,20,4.473432286,4.473432286,6,6,6.0,0.0,0.0,0,0,0,0,1,1,0,0,1,9.0,6.0,6.0,20,1,6,1,6,40880,15544,0,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n5298,69,1,1,0,6,0,0,0.0,0.0,6,6,6.0,0.0,86956.52174,28985.50725,69.0,0.0,69,69,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,40,20,14492.75362,14492.75362,0,6,2.0,3.464101615,12.0,0,0,0,1,0,0,0,0,1,3.0,0.0,6.0,40,1,0,1,6,29200,0,0,40,0.0,0.0,0,0,0.0,0.0,0,0,PortScan,0\n51896,83,1,1,6,6,6,6,6.0,0.0,6,6,6.0,0.0,144578.3133,24096.38554,83.0,0.0,83,83,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,20,20,12048.19277,12048.19277,6,6,6.0,0.0,0.0,0,0,0,0,1,1,0,0,1,9.0,6.0,6.0,20,1,6,1,6,114,252,0,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n80,17,1,1,6,6,6,6,6.0,0.0,6,6,6.0,0.0,705882.3529,117647.0588,17.0,0.0,17,17,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,20,20,58823.52941,58823.52941,6,6,6.0,0.0,0.0,0,0,0,0,1,0,0,0,1,9.0,6.0,6.0,20,1,6,1,6,16425,913,0,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n443,5082688,8,5,348,152,228,0,43.5,77.31198392,85,2,30.4,37.04456775,98.37314429,2.557701752,423557.3333,1443886.986,5008392,3,5082688,726098.2857,1898905.752,5032339,48,50299,12574.75,13986.68789,24766,3,0,0,180,104,1.573970309,0.983731443,0,228,35.71428571,61.53851648,3786.989011,0,0,0,1,0,0,0,0,0,38.46153846,43.5,30.4,180,8,348,5,152,29200,35173,7,20,74248.0,0.0,74248,74248,5008392.0,0.0,5008392,5008392,Normal,0\n53,37119,2,2,96,128,48,48,48.0,0.0,64,64,64.0,0.0,6034.645329885,107.7615237479,12373.0,21424.6024700576,37112,3,4,4.0,0.0,4,4,3,3.0,0.0,3,3,0,0,64,64,53.880761874,53.880761874,48,64,54.4,8.7635609201,76.8,0,0,0,0,0,0,0,0,1,68.0,48.0,64.0,64,2,96,2,128,-1,-1,1,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n443,5169090,11,9,382,3152,183,0,34.72727273,61.08369817,1432,0,350.2222222,566.7655551,683.6793323,3.869152984,272057.3684,1147920.911,5011743,0,5169090,516909.0,1579501.472,5011743,3,106678,13334.75,24254.14011,54281,1,0,0,240,192,2.128034141,1.741118843,0,1432,168.2857143,395.5718826,156477.1143,0,0,0,1,0,0,0,0,0,176.7,34.72727273,350.2222222,240,11,382,9,3152,29200,62,10,20,157344.0,0.0,157344,157344,5011743.0,0.0,5011743,5011743,Normal,0\n53,138,2,2,76,154,38,38,38.0,0.0,77,77,77.0,0.0,1666666.667,28985.50725,46.0,75.34586916,133,2,3,3.0,0.0,3,3,2,2.0,0.0,2,2,0,0,64,64,14492.75362,14492.75362,38,77,53.6,21.36117974,456.3,0,0,0,0,0,0,0,0,1,67.0,38.0,77.0,64,2,76,2,154,-1,-1,1,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n443,66209377,19,18,1529,8484,455,0,80.47368421,142.6823856,1608,0,471.3333333,672.8754801,151.2323549,0.55883323,1839149.361,3764707.407,10000000,4,61800000,3433040.0,4843834.689,10100000,192,66100000,3887813.353,4847607.472,10100000,4,0,0,392,444,0.286968415,0.271864815,0,1608,263.5,507.9583804,258021.7162,0,0,0,1,0,0,0,0,0,270.6216216,80.47368421,471.3333333,392,19,1529,18,8484,8192,262,18,20,307015.0,466740.6787,1259745,116058,9992105.0,20297.3891,10000000,9950683,Normal,0\n57872,4,2,0,37,0,31,6,18.5,17.67766953,0,0,0.0,0.0,9250000.0,500000.0,4.0,0.0,4,4,4,4.0,0.0,4,4,0,0.0,0.0,0,0,1,0,40,0,500000.0,0.0,6,31,22.66666667,14.43375673,208.3333333,0,1,0,0,1,0,0,0,0,34.0,18.5,0.0,40,2,37,0,0,30016,-1,1,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n53,46809,2,2,76,160,38,38,38.0,0.0,80,80,80.0,0.0,5041.765472,85.45365208,15603.0,27019.12658,46802,3,3,3.0,0.0,3,3,4,4.0,0.0,4,4,0,0,64,40,42.72682604,42.72682604,38,80,54.8,23.00434742,529.2,0,0,0,0,0,0,0,0,1,68.5,38.0,80.0,64,2,76,2,160,-1,-1,1,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n7921,24,1,1,0,6,0,0,0.0,0.0,6,6,6.0,0.0,250000.0,83333.33333,24.0,0.0,24,24,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,40,20,41666.66667,41666.66667,0,6,2.0,3.464101615,12.0,0,0,0,1,0,0,0,0,1,3.0,0.0,6.0,40,1,0,1,6,29200,0,0,40,0.0,0.0,0,0,0.0,0.0,0,0,PortScan,0\n58080,3,2,0,0,0,0,0,0.0,0.0,0,0,0.0,0.0,0.0,666666.666666667,3.0,0.0,3,3,3,3.0,0.0,3,3,0,0.0,0.0,0,0,0,0,64,0,666666.666666667,0.0,0,0,0.0,0.0,0.0,0,0,0,0,1,0,0,0,0,0.0,0.0,0.0,64,2,0,0,0,6008,-1,0,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n51086,191,1,1,6,6,6,6,6.0,0.0,6,6,6.0,0.0,62827.22513,10471.20419,191.0,0.0,191,191,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,20,20,5235.602094,5235.602094,6,6,6.0,0.0,0.0,0,0,0,0,1,1,0,0,1,9.0,6.0,6.0,20,1,6,1,6,913,256,0,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n1107,59,1,1,0,6,0,0,0.0,0.0,6,6,6.0,0.0,101694.9153,33898.30508,59.0,0.0,59,59,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,40,20,16949.15254,16949.15254,0,6,2.0,3.464101615,12.0,0,0,0,1,0,0,0,0,1,3.0,0.0,6.0,40,1,0,1,6,29200,0,0,40,0.0,0.0,0,0,0.0,0.0,0,0,PortScan,0\n443,116393116,21,20,1091,3553,652,0,51.95238095,144.9884396,1810,0,177.65,499.4288606,39.89926689,0.35225451,2909827.9,4457457.747,10000000,3,116000000,5819655.8,4955347.945,10200000,3,112000000,5901773.474,5114041.143,10200000,3,0,0,432,408,0.180423042,0.171831468,0,1810,110.5714286,360.6891874,130096.6899,0,0,0,1,0,0,0,0,0,113.2682927,51.95238095,177.65,432,21,1091,20,3553,8192,5272,20,20,211043.6364,217581.0095,867075,145237,9982932.455,61575.69022,10000000,9798471,Normal,0\n80,85630092,6,7,343,11595,325,0,57.16666667,131.2439205,4344,0,1656.428571,1760.597234,139.4136071,0.151815789,7135841.0,24600000.0,85400000,4,85400000,17100000.0,38200000.0,85400000,5,85600000,14300000.0,34900000.0,85400000,15,0,0,164,232,0.070068826,0.081746963,0,4344,853.1428571,1460.251183,2132333.516,1,0,0,0,0,0,0,0,1,918.7692308,57.16666667,1656.428571,164,6,343,7,11595,0,235,3,20,11992.0,0.0,11992,11992,85400000.0,0.0,85400000,85400000,DoS,0\n53,201,2,2,70,102,35,35,35.0,0.0,51,51,51.0,0.0,855721.393,19900.49751,67.0,33.77869151,106,47,48,48.0,0.0,48,48,47,47.0,0.0,47,47,0,0,64,64,9950.248756,9950.248756,35,51,41.4,8.76356092,76.8,0,0,0,0,0,0,0,0,1,51.75,35.0,51.0,64,2,70,2,102,-1,-1,1,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n8080,1019953,3,3,0,18,0,0,0.0,0.0,6,6,6.0,0.0,17.64787201,5.882624003,203990.6,278698.0284,514502,359,1019381,509690.5,7312.191224,514861,504520,1019455,509727.5,7561.092811,515074,504381,0,0,92,60,2.941312002,2.941312002,0,6,2.571428571,3.207134903,10.28571429,0,0,0,1,0,0,0,0,1,3.0,0.0,6.0,92,3,0,3,18,8192,0,0,28,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n80,97819625,8,5,56,11601,20,0,7.0,5.656854249,8760,0,2320.2,3668.897,119.1683162,0.132897668,8151635.417,26700000.0,92900000,1,97200000,13900000.0,34900000.0,92900000,1,683363,170840.75,327034.9589,661148,94,0,0,172,112,0.08178318,0.051114488,0,8760,833.0714286,2337.724089,5464953.918,0,0,0,0,1,0,0,0,0,897.1538462,7.0,2320.2,172,8,56,5,11601,256,229,6,20,4193891.0,0.0,4193891,4193891,92900000.0,0.0,92900000,92900000,DoS,0\n53,214,2,2,102,224,51,51,51.0,0.0,112,112,112.0,0.0,1523364.486,18691.58879,71.33333333,39.55165399,117,48,48,48.0,0.0,48,48,49,49.0,0.0,49,49,0,0,52,40,9345.794393,9345.794393,51,112,75.4,33.41107601,1116.3,0,0,0,0,0,0,0,0,1,94.25,51.0,112.0,52,2,102,2,224,-1,-1,1,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n53,212,2,2,72,172,36,36,36.0,0.0,86,86,86.0,0.0,1150943.396,18867.92453,70.66666667,38.3970485,115,48,48,48.0,0.0,48,48,49,49.0,0.0,49,49,0,0,64,80,9433.962264,9433.962264,36,86,56.0,27.38612788,750.0,0,0,0,0,0,0,0,0,1,70.0,36.0,86.0,64,2,72,2,172,-1,-1,1,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n53,315,2,2,82,254,41,41,41.0,0.0,127,127,127.0,0.0,1066666.667,12698.4127,105.0,180.1360597,313,0,2,2.0,0.0,2,2,0,0.0,0.0,0,0,0,0,56,40,6349.206349,6349.206349,41,127,75.4,47.10413995,2218.8,0,0,0,0,0,0,0,0,1,94.25,41.0,127.0,56,2,82,2,254,-1,-1,1,28,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n53,157,2,2,70,102,35,35,35.0,0.0,51,51,51.0,0.0,1095541.40127389,25477.7070063694,52.3333333333,50.6392469665,105,4,4,4.0,0.0,4,4,48,48.0,0.0,48,48,0,0,64,64,12738.8535031847,12738.8535031847,35,51,41.4,8.7635609201,76.8,0,0,0,0,0,0,0,0,1,51.75,35.0,51.0,64,2,70,2,102,-1,-1,1,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n80,11683143,5,5,449,3525,449,0,89.8,200.7989044,2077,0,705.0,990.6447396,340.1481947,0.855934058,1298127.0,2608773.708,6676538,16,6679580,1669895.0,3338979.336,6678364,242,11700000,2920781.75,3440338.019,6676538,192,0,0,168,168,0.427967029,0.427967029,0,2077,361.2727273,719.4814926,517653.6182,0,0,0,1,0,0,0,0,1,397.4,89.8,705.0,168,5,449,5,3525,29200,235,1,32,868.0,0.0,868,868,6676538.0,0.0,6676538,6676538,DoS,0\n80,85437207,5,7,383,11595,371,0,76.6,164.6019441,4344,0,1656.428571,1760.597234,140.1965305,0.14045403,7767018.818,25700000.0,85300000,4,85300000,21300000.0,42600000.0,85300000,4,85400000,14200000.0,34800000.0,85300000,20,0,0,144,232,0.058522512,0.081931517,0,4344,921.8461538,1497.076309,2241237.474,1,0,0,0,0,0,0,0,1,998.6666667,76.6,1656.428571,144,5,383,7,11595,0,235,2,20,9997.0,0.0,9997,9997,85300000.0,0.0,85300000,85300000,DoS,0\n443,132020,3,0,65,0,53,6,21.66666667,27.13546265,0,0,0.0,0.0,492.349644,22.72382972,66010.0,93346.5804,132016,4,132020,66010.0,93346.5804,132016,4,0,0.0,0.0,0,0,0,0,60,0,22.72382972,0.0,6,53,17.75,23.5,552.25,0,0,0,0,1,0,0,0,0,23.66666667,21.66666667,0.0,60,3,65,0,0,63159,-1,2,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n443,23272,1,1,0,0,0,0,0.0,0.0,0,0,0.0,0.0,0.0,85.94018563,23272.0,0.0,23272,23272,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,32,32,42.97009282,42.97009282,0,0,0.0,0.0,0.0,0,0,0,0,1,1,0,0,1,0.0,0.0,0.0,32,1,0,1,0,1324,2839,0,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n53,60844,2,2,74,444,37,37,37.0,0.0,222,222,222.0,0.0,8513.5757017948,65.7418973112,20281.3333333333,35084.1396977799,60793,3,3,3.0,0.0,3,3,48,48.0,0.0,48,48,0,0,64,64,32.8709486556,32.8709486556,37,222,111.0,101.3286731385,10267.5,0,0,0,0,0,0,0,0,1,138.75,37.0,222.0,64,2,74,2,444,-1,-1,1,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n80,85785254,8,6,374,11595,374,0,46.75,132.2289681,4344,0,1932.5,1754.831473,139.5228136,0.163198211,6598865.692,23800000.0,85700000,1,85700000,12200000.0,32400000.0,85700000,1,132660,26532.0,50672.91702,116328,15,0,0,264,200,0.093256121,0.069942091,0,4344,797.9333333,1424.126723,2028136.924,0,0,0,0,1,0,0,0,0,854.9285714,46.75,1932.5,264,8,374,6,11595,274,235,1,32,978.0,0.0,978,978,85700000.0,0.0,85700000,85700000,DoS,0\n53,163,2,2,66,270,33,33,33.0,0.0,135,135,135.0,0.0,2061349.693,24539.8773,54.33333333,90.64950818,159,1,3,3.0,0.0,3,3,1,1.0,0.0,1,1,0,0,64,64,12269.93865,12269.93865,33,135,73.8,55.86770087,3121.2,0,0,0,0,0,0,0,0,1,92.25,33.0,135.0,64,2,66,2,270,-1,-1,1,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n53,235,2,2,68,484,34,34,34.0,0.0,242,242,242.0,0.0,2348936.17021277,17021.2765957447,78.3333333333,95.4428275636,185,1,49,49.0,0.0,49,49,1,1.0,0.0,1,1,0,0,64,64,8510.6382978724,8510.6382978724,34,242,117.2,113.9262919611,12979.2,0,0,0,0,0,0,0,0,1,146.5,34.0,242.0,64,2,68,2,484,-1,-1,1,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n80,66412,3,5,432,2280,426,0,144.0,244.2375892,1460,2,456.0,659.8545294,40835.9935,120.4601578,9487.428571,15808.31397,32735,1,32828,16414.0,23016.32573,32689,139,33897,8474.25,16386.57433,33048,1,0,0,72,104,45.17255918,75.28759863,0,1460,301.3333333,517.8812605,268201.0,0,0,0,1,0,0,0,0,1,339.0,144.0,456.0,72,3,432,5,2280,8192,30016,2,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n53,49154,2,2,64,120,32,32,32.0,0.0,60,60,60.0,0.0,3743.337267,81.3768971,16384.66667,28375.61105,49150,1,1,1.0,0.0,1,1,3,3.0,0.0,3,3,0,0,40,40,40.68844855,40.68844855,32,60,43.2,15.33623161,235.2,0,0,0,0,0,0,0,0,1,54.0,32.0,60.0,40,2,64,2,120,-1,-1,1,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n443,117940043,15,14,1603,4647,556,0,106.8666667,190.7698189,1448,0,331.9285714,509.6409693,52.99302799,0.24588765,4212144.393,15400000.0,59000000,5,118000000,8424288.786,21300000.0,59000000,173,118000000,9065216.923,22100000.0,59000000,48,0,0,488,456,0.127183267,0.118704383,0,1448,208.3333333,384.9648738,148197.954,0,0,0,1,0,0,0,0,0,215.5172414,106.8666667,331.9285714,488,15,1603,14,4647,29200,131,7,32,240256.5,209086.5254,388103,92410,58700000.0,381297.4323,59000000,58400000,Normal,0\n53,30905,2,2,68,158,34,34,34.0,0.0,79,79,79.0,0.0,7312.7325675457,129.4288950008,10301.6666666667,17838.6800053517,30900,1,4,4.0,0.0,4,4,1,1.0,0.0,1,1,0,0,40,40,64.7144475004,64.7144475004,34,79,52.0,24.6475150877,607.5,0,0,0,0,0,0,0,0,1,65.0,34.0,79.0,40,2,68,2,158,-1,-1,1,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n53,277,2,2,46,46,23,23,23.0,0.0,23,23,23.0,0.0,332129.9639,14440.43321,92.33333333,159.060785,276,0,1,1.0,0.0,1,1,0,0.0,0.0,0,0,0,0,40,40,7220.216606,7220.216606,23,23,23.0,0.0,0.0,0,0,0,0,0,0,0,0,1,28.75,23.0,23.0,40,2,46,2,46,-1,-1,1,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n53,151,2,2,64,96,32,32,32.0,0.0,48,48,48.0,0.0,1059602.649,26490.06623,50.33333333,47.54296303,99,4,4,4.0,0.0,4,4,48,48.0,0.0,48,48,0,0,40,40,13245.03311,13245.03311,32,48,38.4,8.76356092,76.8,0,0,0,0,0,0,0,0,1,48.0,32.0,48.0,40,2,64,2,96,-1,-1,1,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n60052,53107,2,1,0,0,0,0,0.0,0.0,0,0,0.0,0.0,0.0,56.4897282844,26553.5,37497.1654995414,53068,39,53107,53107.0,0.0,53107,53107,0,0.0,0.0,0,0,0,0,76,32,37.6598188563,18.8299094281,0,0,0.0,0.0,0.0,0,0,0,0,1,0,0,0,0,0.0,0.0,0.0,76,2,0,1,0,357,32832,0,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n44912,21,1,1,0,0,0,0,0.0,0.0,0,0,0.0,0.0,0.0,95238.09524,21.0,0.0,21,21,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,32,32,47619.04762,47619.04762,0,0,0.0,0.0,0.0,0,0,0,0,1,0,0,0,1,0.0,0.0,0.0,32,1,0,1,0,5810,40544,0,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n53,33573,1,1,47,79,47,47,47.0,0.0,79,79,79.0,0.0,3753.0158162809,59.5716796235,33573.0,0.0,33573,33573,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,20,20,29.7858398118,29.7858398118,47,79,57.6666666667,18.4752086141,341.3333333333,0,0,0,0,0,0,0,0,1,86.5,47.0,79.0,20,1,47,1,79,-1,-1,0,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n80,23755,1,1,0,0,0,0,0.0,0.0,0,0,0.0,0.0,0.0,84.1928015155,23755.0,0.0,23755,23755,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,32,32,42.0964007577,42.0964007577,0,0,0.0,0.0,0.0,0,0,0,0,1,1,0,0,1,0.0,0.0,0.0,32,1,0,1,0,259,939,0,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n80,11556307,8,6,327,11632,327,0,40.875,115.6119587,4392,0,1938.666667,2190.718847,1034.846167,1.211459682,888946.6923,2192239.144,6553746,3,6557077,936725.2857,2477659.114,6555528,3,11600000,2311251.2,3211628.846,6553746,16,0,0,264,200,0.692262675,0.519197006,0,4392,797.2666667,1628.303958,2651373.781,0,0,0,1,0,0,0,0,0,854.2142857,40.875,1938.666667,264,8,327,6,11632,29200,235,1,32,889.0,0.0,889,889,6553746.0,0.0,6553746,6553746,DoS,0\n50875,104,1,1,0,0,0,0,0.0,0.0,0,0,0.0,0.0,0.0,19230.7692307692,104.0,0.0,104,104,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,32,32,9615.3846153846,9615.3846153846,0,0,0.0,0.0,0.0,0,0,0,0,1,1,0,0,1,0.0,0.0,0.0,32,1,0,1,0,122,33304,0,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n53,419,2,2,64,158,32,32,32.0,0.0,79,79,79.0,0.0,529832.9356,9546.539379,139.6666667,240.177712,417,1,1,1.0,0.0,1,1,1,1.0,0.0,1,1,0,0,40,40,4773.26969,4773.26969,32,79,50.8,25.7429602,662.7,0,0,0,0,0,0,0,0,1,63.5,32.0,79.0,40,2,64,2,158,-1,-1,1,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n53,31057,2,2,94,126,47,47,47.0,0.0,63,63,63.0,0.0,7083.749235,128.7954406,10352.33333,17887.47957,31007,3,3,3.0,0.0,3,3,47,47.0,0.0,47,47,0,0,64,40,64.39772032,64.39772032,47,63,53.4,8.76356092,76.8,0,0,0,0,0,0,0,0,1,66.75,47.0,63.0,64,2,94,2,126,-1,-1,1,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n50847,28,1,1,6,6,6,6,6.0,0.0,6,6,6.0,0.0,428571.428571429,71428.5714285714,28.0,0.0,28,28,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,20,20,35714.2857142857,35714.2857142857,6,6,6.0,0.0,0.0,0,0,0,0,1,1,0,0,1,9.0,6.0,6.0,20,1,6,1,6,60,255,0,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n443,252,2,1,0,0,0,0,0.0,0.0,0,0,0.0,0.0,0.0,11904.7619,126.0,103.2375901,199,53,252,252.0,0.0,252,252,0,0.0,0.0,0,0,0,0,40,32,7936.507937,3968.253968,0,0,0.0,0.0,0.0,1,0,0,0,0,0,0,0,0,0.0,0.0,0.0,40,2,0,1,0,0,972,0,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n5088,23,1,1,6,6,6,6,6.0,0.0,6,6,6.0,0.0,521739.130434783,86956.5217391304,23.0,0.0,23,23,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,20,20,43478.2608695652,43478.2608695652,6,6,6.0,0.0,0.0,0,0,0,0,1,1,0,0,1,9.0,6.0,6.0,20,1,6,1,6,335,258,0,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n53,70440,1,1,49,134,49,49,49.0,0.0,134,134,134.0,0.0,2597.955707,28.39295855,70440.0,0.0,70440,70440,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,32,20,14.19647927,14.19647927,49,134,77.33333333,49.07477288,2408.333333,0,0,0,0,0,0,0,0,1,116.0,49.0,134.0,32,1,49,1,134,-1,-1,0,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n80,15961850,8,4,409,11632,409,0,51.125,144.6033368,11632,0,2908.0,5816.0,754.3611799,0.751792555,1451077.273,3193917.031,9957643,108,11000000,1565670.143,3720045.054,9959668,185,15000000,4987783.0,4978393.831,9957643,899,0,0,272,136,0.501195037,0.250597518,0,11632,926.2307692,3218.668984,10400000.0,0,0,0,1,0,0,0,0,0,1003.416667,51.125,2908.0,272,8,409,4,11632,29200,235,1,32,999400.0,0.0,999400,999400,9957643.0,0.0,9957643,9957643,DoS,0\n80,2080947,6,0,36,0,6,6,6.0,0.0,0,0,0.0,0.0,17.2998159,2.88330265,416189.4,930059.3723,2079930,1,2080947,416189.4,930059.3723,2079930,1,0,0.0,0.0,0,0,0,0,120,0,2.88330265,0.0,6,6,6.0,0.0,0.0,0,0,0,0,1,0,0,0,0,7.0,6.0,0.0,120,6,36,0,0,256,-1,5,20,0.0,0.0,0,0,0.0,0.0,0,0,DoS,0\n42948,27,1,1,0,0,0,0,0.0,0.0,0,0,0.0,0.0,0.0,74074.0740740741,27.0,0.0,27,27,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,32,32,37037.037037037,37037.037037037,0,0,0.0,0.0,0.0,0,0,0,0,1,1,0,0,1,0.0,0.0,0.0,32,1,0,1,0,357,337,0,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n52620,50,1,1,0,0,0,0,0.0,0.0,0,0,0.0,0.0,0.0,40000.0,50.0,0.0,50,50,0,0.0,0.0,0,0,0,0.0,0.0,0,0,0,0,20,20,20000.0,20000.0,0,0,0.0,0.0,0.0,0,0,0,0,1,1,0,0,1,0.0,0.0,0.0,20,1,0,1,0,30,16352,0,20,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n53,66352,2,2,70,102,35,35,35.0,0.0,51,51,51.0,0.0,2592.235350856,60.2845430432,22117.3333333333,38264.1843808715,66301,3,48,48.0,0.0,48,48,3,3.0,0.0,3,3,0,0,64,64,30.1422715216,30.1422715216,35,51,41.4,8.7635609201,76.8,0,0,0,0,0,0,0,0,1,51.75,35.0,51.0,64,2,70,2,102,-1,-1,1,32,0.0,0.0,0,0,0.0,0.0,0,0,Normal,0\n22,11832404,20,33,2008,2745,640,0,100.4,141.9141327,976,0,83.18181818,217.2857356,401.6935189,4.479225016,227546.2308,635795.4507,2928298,4,10200000,535121.7895,949314.8301,2977538,244,11800000,369759.25,781579.42,2928298,4,0,0,648,1064,1.690273591,2.788951425,0,976,88.01851852,189.5902723,35944.47135,0,0,0,1,0,0,0,0,1,89.67924528,100.4,83.18181818,648,20,2008,33,2745,29200,247,16,32,0.0,0.0,0,0,0.0,0.0,0,0,Brute Force,0\n";

  function loadSampleDataset() {
    const loadBtn = document.getElementById('load-sample-csv-btn');
    if (loadBtn) {
      loadBtn.disabled = true;
      loadBtn.innerHTML = '<span>&#x21BA; INGESTING SAMPLE DATASET...</span>';
    }

    function applySampleRecords(csvText) {
      try {
        const records = parseCSVContent(csvText);
        showDashboardView('sample_network_traffic.csv', 'CIC-IDS2017 INGESTED DATASET', records);
        showToast('LOADED SAMPLE DATASET: ' + records.length + ' FLOW RECORDS', 'normal');
      } catch (err) {
        console.error('Error parsing sample CSV:', err);
        const fallbackRecords = generatePresetIncursion();
        showDashboardView('sample_network_traffic.csv (Fallback)', 'CIC-IDS2017 INGESTED DATASET', fallbackRecords);
      } finally {
        if (loadBtn) {
          loadBtn.disabled = false;
          loadBtn.innerHTML = '<span>&#x25C6; LOAD SAMPLE NETWORK DATASET</span>';
        }
      }
    }

    if (window.location.protocol === 'file:') {
      applySampleRecords(EMBEDDED_SAMPLE_CSV);
    } else {
      fetch('./sample_network_traffic.csv')
        .then(res => {
          if (!res.ok) throw new Error('HTTP response not OK');
          return res.text();
        })
        .then(csvText => {
          applySampleRecords(csvText);
        })
        .catch(err => {
          console.warn('Fetch failed, falling back to embedded sample dataset:', err);
          applySampleRecords(EMBEDDED_SAMPLE_CSV);
        });
    }
  }

    function handleFileSelection(file) {
    if (!file) return;

    selectedFileLabel.textContent = `Selected: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
    selectedFileLabel.classList.remove('hidden');

    const reader = new FileReader();
    reader.onload = function (e) {
      try {
        const text = e.target.result;
        uploadedParsedRecords = parseCSVContent(text);
        
        btnAnalyzeCsv.disabled = false;
        btnAnalyzeText.textContent = `ANALYZE CSV LOGS (${uploadedParsedRecords.length} FLOWS)`;
        showToast(`FILE PARSED: ${uploadedParsedRecords.length} VALID FLOW RECORDS READY`, 'normal');
      } catch (err) {
        alert(`Error parsing CSV: ${err.message}`);
        selectedFileLabel.textContent = `Error: Invalid CSV format`;
        btnAnalyzeCsv.disabled = true;
      }
    };
    reader.readAsText(file);
  }

  // ==========================================================================
  // 7. PRESET DEMO DATASET GENERATORS
  // ==========================================================================
  function generatePresetIncursion() {
    const dataset = [];
    const attacks = [
      ATTACK_TEMPLATES[0], // Abnormal TCP flags
      ATTACK_TEMPLATES[1], // SYN flood
      ATTACK_TEMPLATES[2], // Port scan
      ATTACK_TEMPLATES[3], // DNS tunneling
      ATTACK_TEMPLATES[4], // SSH brute
      ATTACK_TEMPLATES[5]  // ICMP exfil
    ];

    // 40 records: 60% attack, 40% benign
    for (let i = 0; i < 40; i++) {
      if (Math.random() < 0.65) {
        dataset.push(generatePacketFlow(randomChoice(attacks)));
      } else {
        dataset.push(generatePacketFlow(randomChoice(BENIGN_TEMPLATES)));
      }
    }
    return dataset;
  }

  function generatePresetSynFlood() {
    const dataset = [];
    const synTemplate = ATTACK_TEMPLATES[1]; // SYN Flood
    for (let i = 0; i < 45; i++) {
      if (Math.random() < 0.85) {
        dataset.push(generatePacketFlow(synTemplate));
      } else {
        dataset.push(generatePacketFlow(BENIGN_TEMPLATES[0]));
      }
    }
    return dataset;
  }

  function generatePresetNominal() {
    const dataset = [];
    for (let i = 0; i < 35; i++) {
      dataset.push(generatePacketFlow(randomChoice(BENIGN_TEMPLATES)));
    }
    return dataset;
  }

  // ==========================================================================
  // 8. METRICS & GAUGE CALCULATION
  // ==========================================================================
  function updateFleetMetrics() {
    const total = flowBuffer.length || 1;
    let normalCount = 0;
    let suspiciousCount = 0;
    let maliciousCount = 0;

    for (let flow of flowBuffer) {
      if (flow.severity === 'normal') normalCount++;
      else if (flow.severity === 'suspicious') suspiciousCount++;
      else if (flow.severity === 'malicious') maliciousCount++;
    }

    const pNormal = ((normalCount / total) * 100).toFixed(1);
    const pSuspicious = ((suspiciousCount / total) * 100).toFixed(1);
    const pMalicious = ((maliciousCount / total) * 100).toFixed(1);

    // Segment widths
    progNormal.style.width = `${pNormal}%`;
    progSuspicious.style.width = `${pSuspicious}%`;
    progMalicious.style.width = `${pMalicious}%`;

    pctNormal.textContent = `${pNormal}%`;
    pctSuspicious.textContent = `${pSuspicious}%`;
    pctMalicious.textContent = `${pMalicious}%`;

    // Dynamic extrapolated totals
    const normScaled = Math.round(totalPacketsTaken * (normalCount / total));
    const suspScaled = Math.round(totalPacketsTaken * (suspiciousCount / total));
    const maliScaled = Math.round(totalPacketsTaken * (maliciousCount / total));

    countNormal.textContent = normScaled.toLocaleString();
    countSuspicious.textContent = suspScaled.toLocaleString();
    countMalicious.textContent = maliScaled.toLocaleString();

    // Risk score formula
    let calculatedRisk = Math.round(
      ((maliciousCount * 4.2 + suspiciousCount * 1.6) / total) * 20 + 8
    );
    calculatedRisk = Math.max(5, Math.min(98, calculatedRisk));

    riskScoreValueElem.textContent = calculatedRisk;

    // Circumference of r=56 is 351.86
    const circumference = 351.86;
    const offset = circumference - (calculatedRisk / 100) * circumference;
    gaugeMeter.style.strokeDashoffset = offset;

    // Risk status evaluation
    if (calculatedRisk < 30) {
      if (riskScoreEvalElem) {
        riskScoreEvalElem.textContent = 'NOMINAL';
        riskScoreEvalElem.style.borderColor = 'var(--col-normal)';
        riskScoreEvalElem.style.color = 'var(--col-normal)';
      }
      if (threatPostureTextElem) {
        threatPostureTextElem.textContent = 'DEFCON 5 (NOMINAL POSTURE)';
        threatPostureTextElem.className = 'meta-value alert-ash';
      }
      gaugeMeter.style.stroke = 'var(--col-normal)';
    } else if (calculatedRisk < 65) {
      if (riskScoreEvalElem) {
        riskScoreEvalElem.textContent = 'ELEVATED';
        riskScoreEvalElem.style.borderColor = 'var(--col-suspicious)';
        riskScoreEvalElem.style.color = 'var(--col-suspicious)';
      }
      if (threatPostureTextElem) {
        threatPostureTextElem.textContent = 'DEFCON 3 (ELEVATED)';
        threatPostureTextElem.className = 'meta-value alert-orange';
      }
      gaugeMeter.style.stroke = 'var(--col-suspicious)';
    } else {
      if (riskScoreEvalElem) {
        riskScoreEvalElem.textContent = 'CRITICAL';
        riskScoreEvalElem.style.borderColor = 'var(--col-malicious)';
        riskScoreEvalElem.style.color = 'var(--col-malicious)';
      }
      if (threatPostureTextElem) {
        threatPostureTextElem.textContent = 'DEFCON 2 (ACTIVE INCURSION)';
        threatPostureTextElem.className = 'meta-value alert-red';
      }
      gaugeMeter.style.stroke = 'var(--col-malicious)';
    }

    // Update classifier chips display if elements exist
    if (chipAbnormal) chipAbnormal.textContent = (classifierTotals['ABNORMAL_TCP_FLAGS'] || 0).toLocaleString();
    if (chipSynFlood) chipSynFlood.textContent = (classifierTotals['SYN_FLOOD'] || 0).toLocaleString();
    if (chipPortScan) chipPortScan.textContent = (classifierTotals['PORT_SCAN'] || 0).toLocaleString();
    if (chipDnsTunnel) chipDnsTunnel.textContent = (classifierTotals['DNS_TUNNELING'] || 0).toLocaleString();
    if (chipSshBrute) chipSshBrute.textContent = (classifierTotals['SSH_BRUTE_FORCE'] || 0).toLocaleString();
    if (chipIcmpExfil) chipIcmpExfil.textContent = (classifierTotals['ICMP_EXFILTRATION'] || 0).toLocaleString();
  }

  // ==========================================================================
  // 9. TABLE RENDERING & FILTERING
  // ==========================================================================
  function createRowElement(flow) {
    const tr = document.createElement('tr');
    tr.id = `row-${flow.id}`;
    tr.className = `flow-${flow.severity} ${flow.isQuarantined ? 'is-quarantined' : ''}`;
    if (flow.id === selectedFlowId) {
      tr.classList.add('row-selected');
    }

    // Timestamp
    const tdTimestamp = document.createElement('td');
    tdTimestamp.className = 'col-timestamp mono';
    tdTimestamp.textContent = flow.timestamp;

    // Source IP
    const tdSource = document.createElement('td');
    tdSource.className = 'col-source mono';
    tdSource.innerHTML = `
      <div class="ip-cluster">
        <span class="ip-addr">${flow.srcIp}</span>
        ${flow.isQuarantined ? '<span class="net-tag" style="color:var(--col-malicious)">[BLOCKED]</span>' : ''}
      </div>
    `;

    // Destination IP
    const tdDest = document.createElement('td');
    tdDest.className = 'col-destination mono';
    tdDest.innerHTML = `
      <div class="ip-cluster">
        <span class="ip-addr">${flow.dstIp}</span>
      </div>
    `;

    // Attack Type
    const tdAttack = document.createElement('td');
    tdAttack.className = 'col-attack';
    const badge = document.createElement('span');
    badge.className = `attack-badge`;
    let icon = flow.severity === 'malicious' ? '&#x26A0;' : flow.severity === 'suspicious' ? '&#x25C6;' : '&#x2713;';
    badge.innerHTML = `${icon} ${flow.attackType}`;
    tdAttack.appendChild(badge);

    // Confidence
    const tdConf = document.createElement('td');
    tdConf.className = 'col-confidence mono';
    tdConf.innerHTML = `
      <div class="confidence-cell-wrap">
        <span class="confidence-val">${flow.confidence}%</span>
        <div class="confidence-mini-bar">
          <div class="confidence-mini-fill" style="width: ${flow.confidence}%"></div>
        </div>
      </div>
    `;

    // Inspect Action
    const tdAction = document.createElement('td');
    tdAction.className = 'col-action';
    const inspectBtn = document.createElement('button');
    inspectBtn.className = 'inspect-btn';
    inspectBtn.textContent = 'INSPECT';
    inspectBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      openInspectionDrawer(flow);
    });
    tdAction.appendChild(inspectBtn);

    tr.appendChild(tdTimestamp);
    tr.appendChild(tdSource);
    tr.appendChild(tdDest);
    tr.appendChild(tdAttack);
    tr.appendChild(tdConf);
    tr.appendChild(tdAction);

    tr.addEventListener('click', () => {
      openInspectionDrawer(flow);
    });

    return tr;
  }

  function getFilteredFlows() {
    return flowBuffer.filter(flow => {
      if (activeFilterMode === 'ATTACKS' && flow.severity === 'normal') {
        return false;
      }
      if (activeChipFilter && flow.attackType !== activeChipFilter) {
        return false;
      }
      if (activeSearchQuery) {
        const q = activeSearchQuery.toLowerCase();
        const matches = (
          flow.srcIp.toLowerCase().includes(q) ||
          flow.dstIp.toLowerCase().includes(q) ||
          flow.attackType.toLowerCase().includes(q) ||
          flow.timestamp.toLowerCase().includes(q)
        );
        if (!matches) return false;
      }
      return true;
    });
  }

  function renderTable() {
    const visibleFlows = getFilteredFlows();
    eventsCountDisplay.textContent = `SHOWING ${visibleFlows.length} EVENTS`;

    tbody.innerHTML = '';
    const fragment = document.createDocumentFragment();
    visibleFlows.forEach(flow => {
      fragment.appendChild(createRowElement(flow));
    });
    tbody.appendChild(fragment);
  }

  function appendNewFlow(flow) {
    flowBuffer.unshift(flow);
    if (flowBuffer.length > MAX_BUFFER_SIZE) {
      flowBuffer.pop();
    }

    totalPacketsTaken += randomInt(18, 52);
    packetCounterElem.textContent = totalPacketsTaken.toLocaleString();

    if (flow.severity === 'malicious') {
      playThreatTone(true);
    } else if (flow.severity === 'suspicious') {
      playThreatTone(false);
    }

    let shouldDisplay = true;
    if (activeFilterMode === 'ATTACKS' && flow.severity === 'normal') shouldDisplay = false;
    if (activeChipFilter && flow.attackType !== activeChipFilter) shouldDisplay = false;
    if (activeSearchQuery) {
      const q = activeSearchQuery.toLowerCase();
      shouldDisplay = (
        flow.srcIp.toLowerCase().includes(q) ||
        flow.dstIp.toLowerCase().includes(q) ||
        flow.attackType.toLowerCase().includes(q) ||
        flow.timestamp.toLowerCase().includes(q)
      );
    }

    if (shouldDisplay) {
      const rowElem = createRowElement(flow);
      tbody.insertBefore(rowElem, tbody.firstChild);

      if (tbody.children.length > MAX_BUFFER_SIZE) {
        tbody.removeChild(tbody.lastChild);
      }
      eventsCountDisplay.textContent = `SHOWING ${tbody.children.length} EVENTS`;
    }

    updateFleetMetrics();
  }

  // ==========================================================================
  // 10. INSPECTION DRAWER & SOC MITIGATION ACTIONS
  // ==========================================================================
  let currentInspectedFlow = null;

  function openInspectionDrawer(flow) {
    currentInspectedFlow = flow;
    selectedFlowId = flow.id;

    document.querySelectorAll('.traffic-table tbody tr').forEach(r => r.classList.remove('row-selected'));
    const targetRow = document.getElementById(`row-${flow.id}`);
    if (targetRow) targetRow.classList.add('row-selected');

    drawerTitle.textContent = `FLOW-ID: #${flow.id}`;
    drawerSeverityBanner.className = `severity-banner ${flow.severity}`;
    
    if (flow.severity === 'normal') {
      drawerSeverityHeading.textContent = `NOMINAL FLOW: ${flow.attackType}`;
      drawerSeverityDesc.textContent = 'Behavior matches standard protocol baseline. No anomaly signature observed.';
    } else if (flow.severity === 'suspicious') {
      drawerSeverityHeading.textContent = `SUSPICIOUS ANOMALY: ${flow.attackType}`;
      drawerSeverityDesc.textContent = flow.desc;
    } else {
      drawerSeverityHeading.textContent = `ACTIVE MALICIOUS INCIDENT: ${flow.attackType}`;
      drawerSeverityDesc.textContent = flow.desc;
    }

    detailTimestamp.textContent = `${flow.timestamp} UTC`;
    detailProtocol.textContent = flow.protocol;
    detailDuration.textContent = `${flow.durationMs} ms`;
    detailSize.textContent = `${flow.packetSize.toLocaleString()} Bytes`;
    detailTtl.textContent = flow.ttl;
    detailGeo.textContent = flow.geo;

    detailSrcIp.textContent = flow.srcIp;
    detailSrcType.textContent = flow.srcTag;
    detailDstIp.textContent = flow.dstIp;
    detailDstType.textContent = flow.dstTag;

    for (let [flagName, elem] of Object.entries(flagElements)) {
      if (elem) {
        elem.className = 'tcp-flag-pill';
        if (flow.tcpFlags.includes(flagName)) {
          elem.classList.add(flow.severity === 'malicious' ? 'alert' : 'active');
        }
      }
    }

    detailWindowSize.textContent = flow.windowSize;
    detailSeq.textContent = flow.seq;
    detailAck.textContent = flow.ack;

    detailEntropy.textContent = `${flow.entropy} / 8.00 (${flow.entropy > 7.0 ? 'HIGH OBSCURATION' : 'NOMINAL STRUCTURE'})`;
    detailEntropyBar.style.width = `${(flow.entropy / 8.0) * 100}%`;

    detailAsymmetry.textContent = `${flow.asymmetry} (${flow.asymmetry > 0.8 ? 'UNIDIRECTIONAL FLOOD' : 'BALANCED BILATERAL'})`;
    detailAsymmetryBar.style.width = `${flow.asymmetry * 100}%`;

    detailConfidenceText.textContent = `${flow.confidence}% (ENSEMBLE RANDOM FOREST + 1D-CNN)`;
    detailConfidenceBar.style.width = `${flow.confidence}%`;

    detailRawHex.textContent = flow.rawHex;

    updateDrawerQuarantineButton();

    drawer.classList.add('open');
    drawer.setAttribute('aria-hidden', 'false');
  }

  function closeInspectionDrawer() {
    drawer.classList.remove('open');
    drawer.setAttribute('aria-hidden', 'true');
    selectedFlowId = null;
    document.querySelectorAll('.traffic-table tbody tr').forEach(r => r.classList.remove('row-selected'));
  }

  function updateDrawerQuarantineButton() {
    if (!currentInspectedFlow) return;
    const ip = currentInspectedFlow.rawSrcIp;
    const isQuarantined = quarantinedHosts.has(ip);

    if (isQuarantined) {
      btnQuarantineHost.classList.add('quarantined');
      quarantineBtnLabel.textContent = `RELEASE HOST [${ip}]`;
    } else {
      btnQuarantineHost.classList.remove('quarantined');
      quarantineBtnLabel.textContent = `QUARANTINE HOST [${ip}]`;
    }
  }

  function toggleQuarantineHost(ip, reason) {
    if (quarantinedHosts.has(ip)) {
      quarantinedHosts.delete(ip);
      showToast(`HOST ${ip} RELEASED FROM ISOLATION. FIREWALL RULES FLUSHED.`, 'normal');
    } else {
      quarantinedHosts.set(ip, {
        ip: ip,
        reason: reason || 'NIDS THREAT HEURISTIC EXCEEDED',
        timestamp: formatUtcTimestamp(new Date()),
        rule: `iptables -A INPUT -s ${ip} -j DROP`
      });
      showToast(`HOST ${ip} ISOLATED! FIREWALL RULE APPLIED: [DROP INGRESS]`, 'malicious');
    }

    flowBuffer.forEach(f => {
      if (f.rawSrcIp === ip || f.rawDstIp === ip) {
        f.isQuarantined = quarantinedHosts.has(f.rawSrcIp) || quarantinedHosts.has(f.rawDstIp);
      }
    });

    updateQuarantineBadges();
    updateDrawerQuarantineButton();
    renderTable();
  }

  function updateQuarantineBadges() {
    const count = quarantinedHosts.size;
    quarantineCountBadge.textContent = count;
    quarantineStatusLine.textContent = `ISOLATION RULES: ${count} HOSTS ACTIVE`;
  }

  // ==========================================================================
  // 11. SNORT IDS RULE & EXPORT GENERATOR
  // ==========================================================================
  function copySnortRule(flow) {
    const sid = 1000000 + Math.floor(Math.random() * 900000);
    const rule = `alert ${flow.protocol.split(' ')[0].toLowerCase()} ${flow.rawSrcIp} any -> ${flow.rawDstIp} ${flow.dstPort} (msg:"AEGIS_NIDS: ${flow.attackType} DETECTED"; flags:${flow.tcpFlags.join('') || '0'}; threshold:type both,track by_src,count 10,seconds 5; classtype:attempted-intrusion; sid:${sid}; rev:1;)`;

    navigator.clipboard.writeText(rule).then(() => {
      showToast(`SNORT IDS RULE COPIED TO CLIPBOARD (SID: ${sid})`, 'normal');
    }).catch(() => {
      prompt('Copy Snort Rule:', rule);
    });
  }

  function exportPcapFile(flow) {
    const pcapDump = [
      `# AEGIS // NIDS FEATURE PACKET CAPTURE`,
      `# FLOW_ID: ${flow.id}`,
      `# TIMESTAMP: ${flow.timestamp} UTC`,
      `# SOURCE: ${flow.srcIp} (${flow.srcTag})`,
      `# DESTINATION: ${flow.dstIp} (${flow.dstTag})`,
      `# PROTOCOL: ${flow.protocol} | TTL: ${flow.ttl} | SIZE: ${flow.packetSize} B`,
      `# TCP_FLAGS: ${flow.tcpFlags.join(', ') || 'NONE'} | WIN: ${flow.windowSize}`,
      `# SHANNON_ENTROPY: ${flow.entropy} / 8.00`,
      `# FLOW_ASYMMETRY: ${flow.asymmetry}`,
      `# NEURAL_CONFIDENCE: ${flow.confidence}%`,
      `# SIGNATURE_LABEL: ${flow.attackType}`,
      `------------------------------------------------------------`,
      flow.rawHex
    ].join('\n');

    const blob = new Blob([pcapDump], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `flow_${flow.id}_${flow.attackType}.pcap.txt`;
    link.click();
    URL.revokeObjectURL(url);
    showToast(`PCAP TELEMETRY SAVED: flow_${flow.id}.pcap.txt`, 'normal');
  }

  function exportBufferToCsv() {
    const headers = ['TIMESTAMP', 'FLOW_ID', 'SOURCE_IP', 'DEST_IP', 'ATTACK_TYPE', 'SEVERITY', 'CONFIDENCE', 'PROTOCOL', 'ENTROPY'];
    const rows = flowBuffer.map(f => [
      f.timestamp,
      f.id,
      f.srcIp,
      f.dstIp,
      f.attackType,
      f.severity,
      f.confidence,
      f.protocol,
      f.entropy
    ]);

    const csvContent = [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `aegis_nids_flow_ledger_${Date.now()}.csv`;
    link.click();
    URL.revokeObjectURL(url);
    showToast(`EXPORTED ${flowBuffer.length} FLOW RECORDS TO CSV`, 'normal');
  }

  // ==========================================================================
  // 12. TOAST NOTIFICATION COMPONENT
  // ==========================================================================
  function showToast(message, type = 'normal') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `
      <span class="toast-msg">${message}</span>
      <button class="toast-close">&times;</button>
    `;

    toast.querySelector('.toast-close').addEventListener('click', () => {
      toast.remove();
    });

    toastContainer.appendChild(toast);
    setTimeout(() => {
      toast.style.transition = 'opacity 0.3s ease';
      toast.style.opacity = '0';
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }

  // ==========================================================================
  // 13. QUARANTINE MODAL
  // ==========================================================================
  function openQuarantineModal() {
    quarantineTbody.innerHTML = '';

    if (quarantinedHosts.size === 0) {
      quarantineTbody.innerHTML = `
        <tr>
          <td colspan="5" style="text-align:center; padding: 24px; color: var(--text-ash);">
            NO CURRENT HOSTS RESTRICTED. NETWORK FIREWALL IN PASS-THROUGH MODE.
          </td>
        </tr>
      `;
    } else {
      quarantinedHosts.forEach((entry) => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td style="color:var(--col-malicious); font-weight:700;">${entry.ip}</td>
          <td>${entry.reason}</td>
          <td>${entry.timestamp}</td>
          <td style="color:var(--col-suspicious);">ACTIVE [DROP]</td>
          <td>
            <button class="unquarantine-btn" data-ip="${entry.ip}">RELEASE</button>
          </td>
        `;
        tr.querySelector('.unquarantine-btn').addEventListener('click', () => {
          toggleQuarantineHost(entry.ip);
          openQuarantineModal();
        });
        quarantineTbody.appendChild(tr);
      });
    }

    quarantineModal.classList.add('open');
    quarantineModal.setAttribute('aria-hidden', 'false');
  }

  function closeQuarantineModal() {
    quarantineModal.classList.remove('open');
    quarantineModal.setAttribute('aria-hidden', 'true');
  }

  // ==========================================================================
  // 14. EVENT LISTENERS SETUP
  // ==========================================================================
  function setupEventListeners() {
    // 1. Theme toggle
    const themeCheckbox = document.getElementById('theme-checkbox');
    const savedTheme = localStorage.getItem('nids_theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);
    themeCheckbox.checked = (savedTheme === 'light');

    themeCheckbox.addEventListener('change', () => {
      const newTheme = themeCheckbox.checked ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', newTheme);
      localStorage.setItem('nids_theme', newTheme);
    });

    // 2. Navigation View Switching
    navIngestionBtn.addEventListener('click', showIngestionView);
    btnSwitchSource.addEventListener('click', showIngestionView);
    brandHomeLink.addEventListener('click', showIngestionView);

    // 3. File Dropzone & Input
    csvFileInput.addEventListener('change', (e) => {
      if (e.target.files && e.target.files[0]) {
        handleFileSelection(e.target.files[0]);
      }
    });

    csvDropzone.addEventListener('dragover', (e) => {
      e.preventDefault();
      csvDropzone.classList.add('drag-over');
    });

    csvDropzone.addEventListener('dragleave', () => {
      csvDropzone.classList.remove('drag-over');
    });

    csvDropzone.addEventListener('drop', (e) => {
      e.preventDefault();
      csvDropzone.classList.remove('drag-over');
      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        handleFileSelection(e.dataTransfer.files[0]);
      }
    });

    btnAnalyzeCsv.addEventListener('click', () => {
      if (uploadedParsedRecords.length > 0) {
        showDashboardView('Uploaded CSV Log', `${uploadedParsedRecords.length} FLOW RECORDS PARSED`, uploadedParsedRecords);
      }
    });

    // 3b. Load Sample Network Dataset Button
    const loadSampleCsvBtn = document.getElementById('load-sample-csv-btn');
    if (loadSampleCsvBtn) {
      loadSampleCsvBtn.addEventListener('click', () => {
        loadSampleDataset();
      });
    }

    // 4. Remote Server Connection Simulation
    btnConnectServer.addEventListener('click', () => {
      const ip = serverIpInput.value.trim() || '192.168.1.100';
      const user = serverUserInput.value.trim() || 'ubuntu';
      const logPath = serverPathInput.value.trim() || '/var/log/network.csv';

      btnConnectServer.disabled = true;
      btnConnectText.textContent = 'Authenticating SSH Socket...';

      setTimeout(() => {
        btnConnectText.textContent = 'Mounting Remote Log Stream...';
        setTimeout(() => {
          btnConnectServer.disabled = false;
          btnConnectText.textContent = 'Connect & Monitor';
          const remoteRecords = generatePresetIncursion();
          showDashboardView(`SSH://${user}@${ip}:${logPath}`, 'REMOTE SOCKET STREAMING ACTIVE', remoteRecords);
        }, 600);
      }, 700);
    });

    // 6. Stream Pause / Resume
    streamToggleBtn.addEventListener('click', () => {
      isStreamPaused = !isStreamPaused;
      if (isStreamPaused) {
        clearInterval(streamTimer);
        streamBtnIcon.innerHTML = '&#x25B6;';
        streamBtnText.textContent = 'RESUME STREAM';
        streamToggleBtn.classList.add('paused');
        showToast('STREAM INGESTION PAUSED', 'suspicious');
      } else {
        startStreamTimer();
        streamBtnIcon.innerHTML = '&#x23F8;';
        streamBtnText.textContent = 'PAUSE STREAM';
        streamToggleBtn.classList.remove('paused');
        showToast('STREAM INGESTION ACTIVE', 'normal');
      }
    });

    // 7. Ingestion Speed selectors
    document.querySelectorAll('.speed-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.speed-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        streamIntervalMs = parseInt(btn.getAttribute('data-speed'), 10);
        if (!isStreamPaused) {
          clearInterval(streamTimer);
          startStreamTimer();
        }
      });
    });

    // 8. Traffic Filter Pills
    const filterAllBtn = document.getElementById('filter-all-btn');
    const filterAttacksBtn = document.getElementById('filter-attacks-btn');

    filterAllBtn.addEventListener('click', () => {
      activeFilterMode = 'ALL';
      filterAllBtn.classList.add('active');
      filterAttacksBtn.classList.remove('active');
      renderTable();
    });

    filterAttacksBtn.addEventListener('click', () => {
      activeFilterMode = 'ATTACKS';
      filterAttacksBtn.classList.add('active');
      filterAllBtn.classList.remove('active');
      renderTable();
    });

    // 9. Search Filter Input
    filterSearchInput.addEventListener('input', (e) => {
      activeSearchQuery = e.target.value.trim();
      clearSearchBtn.classList.toggle('hidden', activeSearchQuery.length === 0);
      renderTable();
    });

    clearSearchBtn.addEventListener('click', () => {
      filterSearchInput.value = '';
      activeSearchQuery = '';
      clearSearchBtn.classList.add('hidden');
      renderTable();
    });

    // 10. Classifier Chips click-to-filter
    document.querySelectorAll('.classifier-chip').forEach(chip => {
      chip.addEventListener('click', () => {
        const attackKey = chip.getAttribute('data-attack');
        if (activeChipFilter === attackKey) {
          activeChipFilter = null;
          chip.classList.remove('active-filter');
        } else {
          document.querySelectorAll('.classifier-chip').forEach(c => c.classList.remove('active-filter'));
          activeChipFilter = attackKey;
          chip.classList.add('active-filter');
        }
        renderTable();
      });
    });

    // 11. Drawer Close
    drawerCloseBtn.addEventListener('click', closeInspectionDrawer);

    // 12. Drawer Mitigation Buttons
    btnQuarantineHost.addEventListener('click', () => {
      if (currentInspectedFlow) {
        toggleQuarantineHost(currentInspectedFlow.rawSrcIp, currentInspectedFlow.attackType);
      }
    });

    btnCopySnort.addEventListener('click', () => {
      if (currentInspectedFlow) copySnortRule(currentInspectedFlow);
    });

    btnExportPcap.addEventListener('click', () => {
      if (currentInspectedFlow) exportPcapFile(currentInspectedFlow);
    });

    // 13. Quarantine Modal Triggers
    quarantineBtn.addEventListener('click', openQuarantineModal);
    modalCloseBtn.addEventListener('click', closeQuarantineModal);
    modalDoneBtn.addEventListener('click', closeQuarantineModal);
    modalClearAllBtn.addEventListener('click', () => {
      quarantinedHosts.clear();
      flowBuffer.forEach(f => f.isQuarantined = false);
      updateQuarantineBadges();
      openQuarantineModal();
      renderTable();
      showToast('ALL HOST QUARANTINES LIFTED. FIREWALL PERMIT ACTIVE.', 'normal');
    });

    // 14. Export Ledger Button
    document.getElementById('export-logs-btn').addEventListener('click', exportBufferToCsv);

    // ESC key closes drawer & modal
    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        closeInspectionDrawer();
        closeQuarantineModal();
      }
    });
  }

  // ==========================================================================
  // 15. INITIALIZATION & STREAM LOOP
  // ==========================================================================
  function startStreamTimer() {
    if (streamTimer) clearInterval(streamTimer);
    streamTimer = setInterval(() => {
      if (!isStreamPaused && !viewDashboard.classList.contains('hidden')) {
        const newFlow = generatePacketFlow();
        appendNewFlow(newFlow);
      }
    }, streamIntervalMs);
  }

  function init() {
    setupEventListeners();
    
    // Start strictly on the Ingestion Portal view ("Start Network Analysis")
    showIngestionView();

    console.log('justdemo: Initialized on Start Network Analysis Portal.');
  }

  // Bootstrap when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
