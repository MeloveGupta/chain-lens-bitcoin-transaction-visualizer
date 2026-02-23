/* ============================================================
   Chain Lens — Frontend Application Logic
   Pure vanilla JS · No external dependencies
   ============================================================ */

/* ---------- State ---------- */
let currentMode = 'tx';

/* ---------- DOM shortcuts ---------- */
const $ = (id) => document.getElementById(id);

/* ---------- Mode switching ---------- */
function switchMode(mode) {
  currentMode = mode;
  $('nav-tx').classList.toggle('active', mode === 'tx');
  $('nav-block').classList.toggle('active', mode === 'block');
  $('tx-input').style.display = mode === 'tx' ? 'block' : 'none';
  $('block-input').style.display = mode === 'block' ? 'block' : 'none';
  $('result').style.display = 'none';
  $('block-result').style.display = 'none';
  $('error-display').style.display = 'none';
}

/* ---------- File input helper ---------- */
function updateFileName(input, nameId, wrapId) {
  const name = input.files[0]?.name || 'Drop or click';
  $(nameId).textContent = name;
  $(wrapId).classList.toggle('has-file', !!input.files[0]);
}

/* ---------- Accordion toggle ---------- */
function toggleDetails(header) {
  const body = header.nextElementSibling;
  body.classList.toggle('open');
  header.querySelector('span').textContent = body.classList.contains('open') ? '▲' : '▼';
}

/* ---------- Formatting helpers ---------- */
function formatSats(sats) {
  if (sats == null) return '—';
  if (sats >= 100_000_000) return (sats / 100_000_000).toFixed(8) + ' BTC';
  return Number(sats).toLocaleString() + ' sats';
}

function badge(type) {
  if (!type) return '';
  const cls = 'badge-' + type.replace(/-/g, '_');
  return '<span class="badge ' + cls + '">' + escHtml(type) + '</span>';
}

function tip(label, text) {
  return '<span class="tip" tabindex="0" role="tooltip">' + label + '<span class="tip-text">' + escHtml(text) + '</span></span>';
}

function mc(title, value, subtitle) {
  return '<div class="metric-card"><h3>' + title + '</h3><div class="value">' + value + '</div>' +
    (subtitle ? '<div class="subtitle">' + subtitle + '</div>' : '') + '</div>';
}

function dr(key, value) {
  return '<div class="detail-row"><span class="detail-key">' + key + '</span><span class="detail-value">' + value + '</span></div>';
}

function escHtml(s) {
  if (typeof s !== 'string') return String(s ?? '');
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

/* ---------- UI state management ---------- */
function showLoading() {
  $('loading').style.display = 'block';
  $('result').style.display = 'none';
  $('block-result').style.display = 'none';
  $('error-display').style.display = 'none';
}

function hideLoading() {
  $('loading').style.display = 'none';
}

function showError(msg) {
  hideLoading();
  const el = $('error-display');
  el.innerHTML = '<div class="error-msg">❌ ' + escHtml(msg) + '</div>';
  el.style.display = 'block';
}

/* ---------- Load sample fixture ---------- */
function loadSample() {
  $('fixture-input').value = JSON.stringify({
    "network": "mainnet",
    "raw_tx": "0200000000010122222222222222222222222222222222222222222222222222222222222222220100000000feffffff02102700000000000016001403030303030303030303030303030303030303038813000000000000225120040404040404040404040404040404040404040404040404040404040404040402471e5180f383a5dcf31ae239e5999f8e6bc8928cd7bbc6c47dc0c596703d009d141c49d1197302d0e4af7dad5035654059faffed5bce60ffbe83a313b957168e894a497524e0a5b421b7934f06d9b55e5d766c1766e4958d7fde1d6c81cdc0dd99e07d65ea8642d86b9000000000",
    "prevouts": [{
      "txid": "2222222222222222222222222222222222222222222222222222222222222222",
      "vout": 1,
      "value_sats": 20000,
      "script_pubkey_hex": "00140505050505050505050505050505050505050505"
    }]
  }, null, 2);
}

/* ============================================================
   TRANSACTION ANALYSIS
   ============================================================ */
async function analyzeTransaction() {
  const input = $('fixture-input').value.trim();
  if (!input) { showError('Please paste a fixture JSON or raw_tx data.'); return; }

  const btn = $('btn-analyze-tx');
  btn.disabled = true;
  showLoading();

  try {
    const fixture = JSON.parse(input);
    const resp = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(fixture)
    });
    const data = await resp.json();
    if (!data.ok) {
      showError(data.error?.message || JSON.stringify(data.error) || 'Unknown error');
      return;
    }
    hideLoading();
    renderTransaction(data);
  } catch (e) {
    showError(e.message);
  } finally {
    hideLoading();
    btn.disabled = false;
  }
}

/* ---------- Render Transaction Result ---------- */
function renderTransaction(d) {
  $('result').style.display = 'block';

  /* 1) Story Card — structured four-section layout */
  const segLabel = d.segwit
    ? 'Yes - witness data (digital signatures) is stored separately, saving block space and reducing fees.'
    : 'No - this is a legacy transaction that doesn\'t use the witness discount.';
  const rbfLabel = d.rbf_signaling
    ? 'The sender flagged this transaction as replaceable - they can resubmit it with a higher fee before it\'s confirmed.'
    : 'The sender did not signal replaceability - this transaction is intended to be final as-is.';

  let lockExplain = 'No timelock set - this transaction can be included in any block right away.';
  if (d.locktime_type === 'block_height')
    lockExplain = 'This transaction can\'t be mined until the blockchain reaches block height ' + d.locktime_value.toLocaleString() + '.';
  else if (d.locktime_type === 'unix_timestamp')
    lockExplain = 'This transaction can\'t be mined before ' + new Date(d.locktime_value * 1000).toUTCString() + '.';

  // Section 1: What happened
  let storyHTML = '<div class="story-section">';
  storyHTML += '<div class="story-section-title">📜 What Happened</div>';
  storyHTML += '<p>This Bitcoin transaction spent <span class="highlight">' +
    d.vin.length + ' ' + tip('input' + (d.vin.length > 1 ? 's' : ''),
      'An input references a previously created output (a "coin") that\'s being spent - think of it like handing over a bill.') +
    '</span> and created <span class="highlight">' +
    d.vout.length + ' ' + tip('output' + (d.vout.length > 1 ? 's' : ''),
      'An output locks bitcoins to a new address. Each one can later be spent as an input in a future transaction.') +
    '</span>.</p></div>';

  // Section 2: What did it cost
  storyHTML += '<div class="story-section">';
  storyHTML += '<div class="story-section-title">💸 What Did It Cost</div>';
  storyHTML += '<p>The sender paid a ' +
    tip('fee', 'The fee is the difference between total inputs and total outputs. Miners collect this as their reward for including the transaction in a block.') +
    ' of <span class="highlight">' + formatSats(d.fee_sats) + '</span> at a rate of <span class="highlight">' +
    d.fee_rate_sat_vb + ' sat/' +
    tip('vB', 'Virtual bytes — a weight-adjusted size unit from SegWit. Smaller vB means lower fees for the same functionality.') +
    '</span>. ' + (d.fee_rate_sat_vb > 50 ? 'That\'s on the higher side - the sender was likely in a hurry.' :
      d.fee_rate_sat_vb < 5 ? 'That\'s quite low - the sender was patient and saved money.' :
        'That\'s a typical rate for normal confirmation speeds.') + '</p></div>';

  // Section 3: Security & Timelocks
  storyHTML += '<div class="story-section">';
  storyHTML += '<div class="story-section-title">🔒 Security &amp; Timelocks</div>';
  storyHTML += '<p><strong>' + tip('SegWit', 'Segregated Witness - a protocol upgrade that moves signature data to a separate section, reducing the effective transaction size and enabling lower fees.') + ':</strong> ' + segLabel + '</p>';
  storyHTML += '<p><strong>' + tip('RBF', 'Replace-By-Fee lets the sender resubmit the transaction with a higher fee if it\'s taking too long to confirm.') + ':</strong> ' + rbfLabel + '</p>';
  storyHTML += '<p><strong>Timelock:</strong> ' + lockExplain + '</p></div>';

  // Section 4: Warnings (if any)
  if (d.warnings && d.warnings.length > 0) {
    const warnMap = {
      HIGH_FEE: 'The fee looks unusually high - the sender may be overpaying for confirmation speed.',
      DUST_OUTPUT: 'One or more outputs are extremely tiny ("dust") - they may cost more to spend later than they\'re worth.',
      UNKNOWN_OUTPUT_SCRIPT: 'An output uses a script type that isn\'t widely recognized.',
      RBF_SIGNALING: 'This transaction is marked as replaceable (RBF) - it could be bumped with a higher fee before confirmation.'
    };
    storyHTML += '<div class="story-section warn">';
    storyHTML += '<div class="story-section-title">⚠️ Anything Risky?</div>';
    storyHTML += '<p>' + d.warnings.map(w => warnMap[w.code] || w.code).join(' ') + '</p></div>';
  } else {
    storyHTML += '<div class="story-section ok">';
    storyHTML += '<div class="story-section-title">✅ All Clear</div>';
    storyHTML += '<p>No warnings detected - this transaction looks normal and doesn\'t raise any red flags.</p></div>';
  }

  $('story-narrative').innerHTML = storyHTML;

  /* 2) Metric cards */
  $('metrics-grid').innerHTML =
    mc('Transaction ID', '<span style="font-size:11px;font-family:var(--mono);word-break:break-all">' + escHtml(d.txid) + '</span>', '') +
    mc(tip('Fee', 'Total satoshis paid to the miner as an incentive.'), '<span style="color:var(--accent)">' + formatSats(d.fee_sats) + '</span>', d.fee_rate_sat_vb + ' sat/vB') +
    mc('Inputs / Outputs', d.vin.length + ' → ' + d.vout.length, '') +
    mc('Size & Weight', d.vbytes + ' vB', d.size_bytes + ' bytes · weight ' + d.weight) +
    mc('Type', d.segwit ? '<span class="badge badge-segwit">SegWit</span>' : 'Legacy', 'Version ' + d.version) +
    '<div class="metric-card"><h3>Output Script Types</h3><div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:8px">' +
    d.vout.map(o => badge(o.script_type)).join('') + '</div></div>';

  /* 3) Warnings bar */
  let wHTML = '';
  if (d.warnings && d.warnings.length > 0) {
    const labels = {
      HIGH_FEE: '⚠️ High Fee', DUST_OUTPUT: '🪙 Dust Output',
      UNKNOWN_OUTPUT_SCRIPT: '❓ Unknown Script', RBF_SIGNALING: '🔄 RBF Signaling'
    };
    d.warnings.forEach(w => {
      wHTML += '<span class="badge badge-warning">' + (labels[w.code] || w.code) + '</span>';
    });
  }
  $('warnings-section').innerHTML = wHTML;

  /* 4) Flow graph — inputs on left, outputs + fee on right */
  let inHTML = '<h4>' + tip('Inputs', 'Inputs reference previously created outputs (UTXOs) being spent in this transaction.') + '</h4>';
  d.vin.forEach(inp => {
    const val = inp.prevout ? inp.prevout.value_sats : null;
    inHTML += '<div class="flow-item input"><div class="amount">' + formatSats(val) + '</div>' +
      '<div class="label">' + badge(inp.script_type) +
      (inp.address ? '<br><span style="font-family:var(--mono);font-size:11px">' + escHtml(inp.address).substring(0, 24) + '…</span>' : '') +
      '</div></div>';
  });

  let outHTML = '<h4>' + tip('Outputs', 'Outputs lock bitcoins to a script/address. Each can later be spent as an input.') + '</h4>';
  d.vout.forEach(o => {
    outHTML += '<div class="flow-item output"><div class="amount">' + formatSats(o.value_sats) + '</div>' +
      '<div class="label">' + badge(o.script_type) +
      (o.address ? '<br><span style="font-family:var(--mono);font-size:11px">' + escHtml(o.address).substring(0, 24) + '…</span>' : '') +
      '</div></div>';
  });
  outHTML += '<div class="flow-item fee"><div class="amount">' + formatSats(d.fee_sats) + '</div>' +
    '<div class="label">Miner ' + tip('Fee', 'The fee incentivizes miners to include the transaction. It equals total inputs minus total outputs - the "missing" amount.') + '</div></div>';

  $('flow-graph').innerHTML =
    '<div class="flow-column">' + inHTML + '</div>' +
    '<div class="flow-center"><div class="flow-arrow">→</div></div>' +
    '<div class="flow-column">' + outHTML + '</div>';

  /* 5) SegWit savings visualization */
  if (d.segwit_savings) {
    const ss = d.segwit_savings;
    $('segwit-section').style.display = 'block';
    $('segwit-body').innerHTML =
      '<div class="savings-compare">' +
      '<div class="savings-box"><div class="sz-label">Actual Weight</div><div class="sz-value">' + ss.weight_actual + '</div></div>' +
      '<div class="savings-box"><div class="sz-label">Weight If Legacy</div><div class="sz-value">' + ss.weight_if_legacy + '</div></div>' +
      '</div>' +
      '<div class="savings-pct">💡 Saving ' + ss.savings_pct + '% with SegWit</div>' +
      dr('Non-witness bytes', ss.non_witness_bytes) +
      dr('Witness bytes', ss.witness_bytes) +
      dr('Total bytes', ss.total_bytes);
  } else {
    $('segwit-section').style.display = 'none';
  }

  /* 6) Technical details (hidden by default — toggled by accordion) */
  let techHTML = '';
  techHTML += dr('TXID', escHtml(d.txid));
  if (d.wtxid) techHTML += dr('WTXID', escHtml(d.wtxid));
  techHTML += dr('Version', d.version);
  techHTML += dr('Locktime', d.locktime_value + ' (' + d.locktime_type + ')');
  techHTML += dr('RBF Signaling', d.rbf_signaling ? '✅ Yes' : '❌ No');
  techHTML += dr('Total In', formatSats(d.total_input_sats));
  techHTML += dr('Total Out', formatSats(d.total_output_sats));
  techHTML += dr('Fee', formatSats(d.fee_sats) + ' (' + d.fee_rate_sat_vb + ' sat/vB)');
  $('tech-details').innerHTML = techHTML;

  /* 7) Inputs detail — humanized labels */
  let idHTML = '';
  d.vin.forEach((inp, i) => {
    const seqHex = '0x' + inp.sequence.toString(16).padStart(8, '0');
    const seqHint = inp.sequence === 0xFFFFFFFF ? '(final — no RBF, no relative timelock)' :
      inp.sequence === 0xFFFFFFFE ? '(final — no RBF, but allows absolute timelock)' :
        inp.sequence < 0xFFFFFFFE ? '(signals RBF replaceability)' : '';
    idHTML += '<div style="margin-bottom:16px;padding:12px;background:var(--bg-secondary);border-radius:var(--radius-sm)">' +
      '<div style="font-weight:600;margin-bottom:8px">Input #' + (i + 1) + ' ' + badge(inp.script_type) + '</div>' +
      dr('Spending from TX', '<span style="font-size:11px">' + escHtml(inp.txid) + '</span>') +
      dr('Output index', inp.vout) +
      dr(tip('Sequence', 'The sequence number controls Replace-By-Fee (RBF) signaling and relative timelocks. Lower values signal that the sender can replace this transaction.'), seqHex + ' <span style="color:var(--text-secondary);font-size:11px">' + seqHint + '</span>') +
      (inp.prevout ? dr('Value being spent', formatSats(inp.prevout.value_sats)) : '') +
      (inp.address ? dr('From address', escHtml(inp.address)) : '') +
      dr('ScriptSig', escHtml(inp.script_sig_hex) || '<span style="color:var(--text-muted)">(empty — typical for SegWit)</span>') +
      (inp.script_asm ? dr('Script (decoded)', '<span style="font-size:10px">' + escHtml(inp.script_asm) + '</span>') : '') +
      (inp.witness && inp.witness.length ? dr(tip('Witness', 'The witness section contains the digital signatures and proofs needed to authorize this spend.'), '<span style="font-size:10px">' + inp.witness.map(escHtml).join(' ') + '</span>') : '') +
      (inp.relative_timelock && inp.relative_timelock.enabled ? dr('Relative timelock', inp.relative_timelock.type === 'blocks' ? inp.relative_timelock.value + ' blocks' : inp.relative_timelock.value + ' seconds') : '') +
      '</div>';
  });
  $('inputs-detail').innerHTML = idHTML;

  /* 8) Outputs detail — humanized labels */
  let odHTML = '';
  d.vout.forEach(o => {
    odHTML += '<div style="margin-bottom:16px;padding:12px;background:var(--bg-secondary);border-radius:var(--radius-sm)">' +
      '<div style="font-weight:600;margin-bottom:8px">Output #' + (o.n + 1) + ' ' + badge(o.script_type) + '</div>' +
      dr('Amount', formatSats(o.value_sats)) +
      (o.address ? dr('To address', escHtml(o.address)) : '') +
      dr('Locking script', '<span style="font-size:11px">' + escHtml(o.script_pubkey_hex) + '</span>') +
      dr('Script (decoded)', '<span style="font-size:10px">' + escHtml(o.script_asm) + '</span>') +
      (o.script_type === 'op_return'
        ? dr(tip('OP_RETURN', 'OP_RETURN outputs store arbitrary data on the blockchain. They are provably unspendable - nobody can ever spend these coins.') + ' data', escHtml(o.op_return_data_hex || '')) +
        (o.op_return_data_utf8 ? dr('Data (readable)', escHtml(o.op_return_data_utf8)) : '') +
        (o.op_return_protocol && o.op_return_protocol !== 'unknown' ? dr('Detected protocol', escHtml(o.op_return_protocol)) : '')
        : '') +
      '</div>';
  });
  $('outputs-detail').innerHTML = odHTML;
}

/* ============================================================
   BLOCK ANALYSIS
   ============================================================ */
async function analyzeBlock() {
  const blkFile = $('blk-file').files[0];
  const revFile = $('rev-file').files[0];
  const xorFile = $('xor-file').files[0];
  if (!blkFile || !revFile || !xorFile) {
    showError('Please select all three files: blk*.dat, rev*.dat, and xor.dat');
    return;
  }

  const btn = $('btn-analyze-block');
  btn.disabled = true;
  showLoading();

  try {
    const form = new FormData();
    form.append('blk', blkFile);
    form.append('rev', revFile);
    form.append('xor', xorFile);

    const resp = await fetch('/api/analyze_block', {
      method: 'POST',
      body: form
    });
    const data = await resp.json();
    if (!data.ok) {
      showError(data.error?.message || JSON.stringify(data.error) || 'Unknown error');
      return;
    }
    hideLoading();
    renderBlockResult(data.blocks);
  } catch (e) {
    showError(e.message);
  } finally {
    hideLoading();
    btn.disabled = false;
  }
}

/* ---------- Render Block Result ---------- */
function renderBlockResult(blocks) {
  $('block-result').style.display = 'block';
  const b = blocks[0];
  if (!b) { showError('No blocks found in uploaded files.'); return; }

  const h = b.block_header;

  /* Overview metric cards */
  $('block-overview').innerHTML =
    mc('Block Hash', '<span style="font-size:11px;font-family:var(--mono);word-break:break-all">' + escHtml(h.block_hash) + '</span>', '') +
    mc('Transactions', b.tx_count, 'BIP34 Height: ' + (b.coinbase?.bip34_height ?? '—')) +
    mc('Total Fees', '<span style="color:var(--accent)">' + formatSats(b.block_stats.total_fees_sats) + '</span>',
      'Avg ' + b.block_stats.avg_fee_rate_sat_vb + ' sat/vB') +
    mc('Merkle Root', '<span style="color:' + (h.merkle_root_valid ? 'var(--green)' : 'var(--red)') + '">' +
      (h.merkle_root_valid ? '✅ Valid' : '❌ Invalid') + '</span>', '');

  /* Block story */
  $('block-story').innerHTML =
    '<strong>Block Summary:</strong> This block contains <span class="highlight">' + b.tx_count +
    ' transactions</span>. The miners collected a total of <span class="highlight">' +
    formatSats(b.block_stats.total_fees_sats) + '</span> in fees, with an average fee rate of <span class="highlight">' +
    b.block_stats.avg_fee_rate_sat_vb + ' sat/' + tip('vB', 'Virtual bytes - a weight-adjusted size unit.') +
    '</span>. The ' + tip('Merkle root', 'A cryptographic hash that summarizes all transactions in the block. If valid, it proves no transactions were tampered with.') +
    ' is ' + (h.merkle_root_valid ? '<span style="color:var(--green)">valid ✅</span>' : '<span style="color:var(--red)">invalid ❌</span>') + '.';

  /* Transaction list — each expandable */
  let txHTML = '';
  b.transactions.forEach((tx, i) => {
    const isCb = i === 0;
    txHTML +=
      '<div class="tx-list-item" onclick="this.nextElementSibling.classList.toggle(\'open\')">' +
      '<span>' + (isCb ? '🪙 Coinbase' : 'TX #' + i) + '</span>' +
      '<span class="txid-short">' + escHtml(tx.txid.substring(0, 16)) + '…</span>' +
      '<span>' + formatSats(isCb ? tx.total_output_sats : tx.fee_sats) + ' ' + (isCb ? 'reward' : 'fee') + '</span>' +
      '</div>' +
      '<div class="details-body" style="padding:12px;background:var(--bg-secondary)">' +
      dr('TXID', escHtml(tx.txid)) +
      dr('Inputs', tx.vin.length) +
      dr('Outputs', tx.vout.length) +
      dr('Weight', tx.weight) +
      (!isCb ? dr('Fee', formatSats(tx.fee_sats) + ' (' + tx.fee_rate_sat_vb + ' sat/vB)') : '') +
      '<div style="margin-top:8px">' + tx.vout.map(o => badge(o.script_type)).join(' ') + '</div>' +
      '</div>';
  });
  $('block-tx-list').innerHTML = '<div class="tx-list">' + txHTML + '</div>';
}
