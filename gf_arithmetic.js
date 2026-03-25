/* ============================================================
   GF(2^m) Polynomial Arithmetic Calculator
   EECE 455/632 - Cryptography & Network Security

   All arithmetic uses BigInt for arbitrary-degree support.
   ============================================================ */

// ===================== CONSTANTS =====================

// Default irreducible polynomials (from project spec for 2-8, standard for 9-16)
const IRREDUCIBLE_DEFAULTS = {
  2:  0x7n,       // x^2 + x + 1
  3:  0xDn,       // x^3 + x^2 + 1
  4:  0x19n,      // x^4 + x^3 + 1
  5:  0x25n,      // x^5 + x^2 + 1
  6:  0x43n,      // x^6 + x + 1
  7:  0x83n,      // x^7 + x + 1
  8:  0x11Bn,     // x^8 + x^4 + x^3 + x + 1
  9:  0x211n,     // x^9 + x^4 + 1
  10: 0x409n,     // x^10 + x^3 + 1
  11: 0x805n,     // x^11 + x^2 + 1
  12: 0x1053n,    // x^12 + x^6 + x^4 + x + 1
  13: 0x201Bn,    // x^13 + x^4 + x^3 + x + 1
  14: 0x4443n,    // x^14 + x^10 + x^6 + x + 1
  15: 0x8003n,    // x^15 + x + 1
  16: 0x1002Dn,   // x^16 + x^5 + x^3 + x^2 + 1
};

const SUP_CHARS = '\u2070\u00B9\u00B2\u00B3\u2074\u2075\u2076\u2077\u2078\u2079';
const SUP_MAP = {};
for (let i = 0; i < 10; i++) SUP_MAP[SUP_CHARS[i]] = String(i);

// ===================== FORMATTING UTILITIES =====================

function sup(n) {
  return String(n).split('').map(d => SUP_CHARS[parseInt(d)]).join('');
}

function degree(p) {
  if (p === 0n) return -1;
  return p.toString(2).length - 1;
}

function polyStr(p) {
  if (p === 0n) return '0';
  const terms = [];
  const deg = degree(p);
  for (let i = deg; i >= 0; i--) {
    if (p & (1n << BigInt(i))) {
      if (i === 0)      terms.push('1');
      else if (i === 1) terms.push('x');
      else              terms.push('x' + sup(i));
    }
  }
  return terms.join(' + ');
}

function toBin(p, minBits) {
  if (p === 0n) return '0'.padStart(minBits || 1, '0');
  let s = p.toString(2);
  if (minBits && s.length < minBits) s = s.padStart(minBits, '0');
  return s;
}

function toHex(p) {
  return p === 0n ? '0' : p.toString(16).toUpperCase();
}

// ===================== POLYNOMIAL PARSER =====================

// Parses a polynomial expression string into a BigInt bit-vector.
// Supports: x^5 + x^2 + 1, 3x^5 + 2x^2, x5+x2+1, x+1, etc.
// Coefficients are reduced mod 2 (GF(2)).
// Also handles unicode superscripts from copy-paste.
function parsePoly(str) {
  str = str.trim();
  if (str === '' || str === '0') return 0n;

  // Replace unicode superscripts with ^N
  str = str.replace(new RegExp(`[${SUP_CHARS}]+`, 'g'), match => {
    return '^' + match.split('').map(c => SUP_MAP[c] || c).join('');
  });

  // Normalize: treat - as + (in GF(2), additive inverse = self)
  str = str.replace(/\-/g, '+');
  // Remove all spaces
  str = str.replace(/\s+/g, '');

  const terms = str.split('+').filter(t => t !== '');
  let result = 0n;

  for (const term of terms) {
    let coeff, power;

    // Order matters: try most specific patterns first
    let m;
    if ((m = term.match(/^(\d+)\*?x\^(\d+)$/i))) {
      // Cx^N  (e.g., 3x^5, 3*x^5)
      coeff = parseInt(m[1]);
      power = parseInt(m[2]);
    } else if ((m = term.match(/^x\^(\d+)$/i))) {
      // x^N  (e.g., x^5)
      coeff = 1;
      power = parseInt(m[1]);
    } else if ((m = term.match(/^(\d+)\*?x(\d+)$/i))) {
      // CxN  (e.g., 3x5 — shorthand)
      coeff = parseInt(m[1]);
      power = parseInt(m[2]);
    } else if ((m = term.match(/^x(\d+)$/i))) {
      // xN  (e.g., x5 — shorthand for x^5)
      coeff = 1;
      power = parseInt(m[1]);
    } else if ((m = term.match(/^(\d+)\*?x$/i))) {
      // Cx  (e.g., 3x, 3*x)
      coeff = parseInt(m[1]);
      power = 1;
    } else if ((m = term.match(/^x$/i))) {
      // x
      coeff = 1;
      power = 1;
    } else if ((m = term.match(/^(\d+)$/))) {
      // N  (constant)
      coeff = parseInt(m[1]);
      power = 0;
    } else {
      return null; // parse error
    }

    // In GF(2), coefficients are mod 2 — toggle the bit
    if (coeff % 2 === 1) {
      result ^= (1n << BigInt(power));
    }
  }

  return result;
}

// ===================== CORE GF(2^m) MATH =====================

// Raw polynomial multiplication (no mod reduction), using BigInt
function mulRaw(a, b) {
  let result = 0n;
  let shift = 0n;
  let bb = b;
  while (bb > 0n) {
    if (bb & 1n) result ^= (a << shift);
    bb >>= 1n;
    shift++;
  }
  return result;
}

// Polynomial divmod over GF(2): returns [quotient, remainder]
function polyDivMod(a, b) {
  if (b === 0n) return null;
  let q = 0n, r = a;
  while (r !== 0n && degree(r) >= degree(b)) {
    const shift = degree(r) - degree(b);
    q ^= (1n << BigInt(shift));
    r ^= (b << BigInt(shift));
  }
  return [q, r];
}

// Simple mod reduction (no step tracking)
function reduceSimple(a, irr) {
  const m = degree(irr);
  let p = a;
  while (p !== 0n && degree(p) >= m) {
    p ^= (irr << BigInt(degree(p) - m));
  }
  return p;
}

// ===================== OPERATIONS WITH STEPS =====================

function opAdd(a, b, m, irr) {
  const steps = [];
  steps.push({ label: 'Operation', text: `${polyStr(a)}  \u2295  ${polyStr(b)}`, section: true });
  steps.push({ label: 'Binary XOR', text: `${toBin(a, m)} \u2295 ${toBin(b, m)}` });
  const result = a ^ b;
  steps.push({ label: 'Result', text: `${toBin(result, m)}  =  ${polyStr(result)}`, highlight: true });
  return { result, steps };
}

function opSub(a, b, m, irr) {
  const steps = [];
  steps.push({ label: 'Operation', text: `${polyStr(a)}  \u2296  ${polyStr(b)}`, section: true });
  steps.push({ label: 'Note', text: 'In GF(2), subtraction is identical to addition (XOR)', section: true });
  steps.push({ label: 'Binary XOR', text: `${toBin(a, m)} \u2295 ${toBin(b, m)}` });
  const result = a ^ b;
  steps.push({ label: 'Result', text: `${toBin(result, m)}  =  ${polyStr(result)}`, highlight: true });
  return { result, steps };
}

function opMod(a, m, irr) {
  const steps = [];
  steps.push({ label: 'Operation', text: `Reduce ${polyStr(a)} mod ${polyStr(irr)}`, section: true });
  steps.push({ label: 'Input', text: `${toBin(a)} (degree ${degree(a)})` });

  if (degree(a) < m) {
    steps.push({ label: 'No reduction', text: `Degree ${degree(a)} < ${m}, already in the field` });
    steps.push({ label: 'Result', text: `${toBin(a, m)}  =  ${polyStr(a)}`, highlight: true });
    return { result: a, steps };
  }

  let p = a;
  let stepNum = 1;
  while (p !== 0n && degree(p) >= m) {
    const shift = degree(p) - m;
    const shifted = irr << BigInt(shift);
    steps.push({
      label: `Step ${stepNum}`,
      text: `deg = ${degree(p)} \u2265 ${m} \u2192 XOR with (${polyStr(irr)}) \u00AB ${shift}`
    });
    const prev = p;
    p ^= shifted;
    steps.push({
      label: 'XOR',
      text: `${toBin(prev)} \u2295 ${toBin(shifted)} = ${toBin(p)}`
    });
    stepNum++;
  }

  steps.push({ label: 'Result', text: `${toBin(p, m)}  =  ${polyStr(p)}`, highlight: true });
  return { result: p, steps };
}

function opMul(a, b, m, irr) {
  const steps = [];
  steps.push({ label: 'Operation', text: `(${polyStr(a)}) \u00D7 (${polyStr(b)})`, section: true });
  steps.push({ label: 'Step 1', text: 'Polynomial multiplication (shift-and-XOR)', section: true });

  let product = 0n;
  let bb = b;
  let i = 0;
  while (bb > 0n) {
    if (bb & 1n) {
      const partial = a << BigInt(i);
      steps.push({
        label: `Bit ${i} of B = 1`,
        text: `A \u00AB ${i} = ${toBin(partial)}  (${polyStr(partial)})`
      });
      product ^= partial;
    }
    bb >>= 1n;
    i++;
  }

  steps.push({ label: 'Raw product', text: `${toBin(product)}  =  ${polyStr(product)}` });

  if (degree(product) >= m) {
    steps.push({ label: 'Step 2', text: `Reduce mod ${polyStr(irr)}`, section: true });
    let p = product;
    let stepNum = 1;
    while (p !== 0n && degree(p) >= m) {
      const shift = degree(p) - m;
      const shifted = irr << BigInt(shift);
      const prev = p;
      p ^= shifted;
      steps.push({
        label: `Reduce ${stepNum}`,
        text: `${toBin(prev)} \u2295 ${toBin(shifted)} = ${toBin(p)}`
      });
      stepNum++;
    }
    steps.push({ label: 'Result', text: `${toBin(p, m)}  =  ${polyStr(p)}`, highlight: true });
    return { result: p, steps };
  }

  steps.push({ label: 'No reduction', text: `Degree ${degree(product)} < ${m}` });
  steps.push({ label: 'Result', text: `${toBin(product, m)}  =  ${polyStr(product)}`, highlight: true });
  return { result: product, steps };
}

function opInverse(a, m, irr) {
  const steps = [];

  if (a === 0n) {
    steps.push({ label: 'Error', text: '0 has no multiplicative inverse', error: true });
    return { result: null, steps };
  }

  steps.push({ label: 'Operation', text: `Find (${polyStr(a)})\u207B\u00B9 in GF(2${sup(m)})`, section: true });
  steps.push({ label: 'Method', text: 'Extended Euclidean Algorithm on GF(2) polynomials', section: true });
  steps.push({ label: 'Goal', text: `Find x: (${polyStr(a)}) \u00B7 x \u2261 1  (mod ${polyStr(irr)})` });

  let old_r = a, r = irr;
  let old_s = 1n, s = 0n;
  let iteration = 0;

  steps.push({ label: 'Init', text: `r\u2080 = ${polyStr(old_r)},  s\u2080 = ${polyStr(old_s)}` });
  steps.push({ label: 'Init', text: `r\u2081 = ${polyStr(r)},  s\u2081 = ${polyStr(s)}` });

  while (r !== 0n) {
    const [q, rem] = polyDivMod(old_r, r);
    const qs = mulRaw(q, s);
    const new_s = old_s ^ qs;
    iteration++;

    steps.push({
      label: `Iter ${iteration}`,
      text: `${polyStr(old_r)} \u00F7 ${polyStr(r)}  \u2192  q = ${polyStr(q)},  rem = ${polyStr(rem)}`,
      section: iteration > 1
    });
    steps.push({
      label: 'Coeff update',
      text: `s = ${polyStr(old_s)} \u2295 (${polyStr(q)} \u00B7 ${polyStr(s)}) = ${polyStr(new_s)}`
    });

    old_r = r;
    r = rem;
    old_s = s;
    s = new_s;
  }

  if (old_r !== 1n) {
    steps.push({ label: 'Error', text: `GCD = ${polyStr(old_r)} \u2260 1, no inverse exists`, error: true });
    return { result: null, steps };
  }

  let inv = old_s;
  if (degree(inv) >= m) {
    const reduced = reduceSimple(inv, irr);
    steps.push({ label: 'Reduce', text: `${polyStr(inv)} mod ${polyStr(irr)} = ${polyStr(reduced)}` });
    inv = reduced;
  }

  steps.push({ label: 'Inverse', text: `${polyStr(inv)}`, highlight: true });

  // Verification
  const check = reduceSimple(mulRaw(a, inv), irr);
  steps.push({
    label: 'Verify',
    text: `(${polyStr(a)}) \u00D7 (${polyStr(inv)}) mod ${polyStr(irr)} = ${polyStr(check)} \u2713`
  });

  return { result: inv, steps };
}

function opDiv(a, b, m, irr) {
  const steps = [];

  if (b === 0n) {
    steps.push({ label: 'Error', text: 'Division by zero is undefined', error: true });
    return { result: null, steps };
  }

  steps.push({ label: 'Operation', text: `(${polyStr(a)}) \u00F7 (${polyStr(b)}) in GF(2${sup(m)})`, section: true });
  steps.push({ label: 'Method', text: 'Division = A \u00D7 B\u207B\u00B9', section: true });

  // Find inverse of B
  steps.push({ label: 'Step 1', text: `Find inverse of B = ${polyStr(b)}`, section: true });
  const invResult = opInverse(b, m, irr);
  for (const s of invResult.steps) steps.push(s);

  if (invResult.result === null) return { result: null, steps };

  const bInv = invResult.result;

  // Multiply A by B^-1
  steps.push({ label: 'Step 2', text: `Multiply A \u00D7 B\u207B\u00B9 = (${polyStr(a)}) \u00D7 (${polyStr(bInv)})`, section: true });

  const rawProduct = mulRaw(a, bInv);
  steps.push({ label: 'Raw product', text: `${toBin(rawProduct)}  =  ${polyStr(rawProduct)}` });

  const result = reduceSimple(rawProduct, irr);
  if (degree(rawProduct) >= m) {
    steps.push({ label: 'Reduce', text: `mod ${polyStr(irr)} = ${polyStr(result)}` });
  }

  steps.push({ label: 'Result', text: `(${polyStr(a)}) \u00F7 (${polyStr(b)}) = ${polyStr(result)}`, highlight: true });
  return { result, steps };
}

// ===================== UI CONTROLLER =====================

const App = {
  m: 8,
  format: 'bin',
  irr: IRREDUCIBLE_DEFAULTS[8],
  lastResult: null,

  init() {
    this.buildDegreeButtons();
    this.bindEvents();
    this.updateIrreducibleDisplay();
    this.updatePlaceholders();
  },

  buildDegreeButtons() {
    const container = document.getElementById('degree-btns');
    for (let d = 2; d <= 8; d++) {
      const btn = document.createElement('button');
      btn.textContent = d;
      btn.dataset.degree = d;
      if (d === this.m) btn.classList.add('active');
      btn.addEventListener('click', () => this.setDegree(d));
      container.appendChild(btn);
    }
  },

  bindEvents() {
    // Degree number input
    const degInput = document.getElementById('degree-input');
    degInput.addEventListener('change', () => {
      let val = parseInt(degInput.value);
      if (isNaN(val) || val < 2) val = 2;
      if (val > 128) val = 128;
      degInput.value = val;
      this.setDegree(val);
    });

    // Format toggle
    document.querySelectorAll('#format-toggle button').forEach(btn => {
      btn.addEventListener('click', () => this.setFormat(btn.dataset.format));
    });

    // Irreducible polynomial input
    document.getElementById('irr-input').addEventListener('input', () => this.onIrrInput());
    document.getElementById('irr-reset').addEventListener('click', () => this.resetIrreducible());

    // Input live preview
    document.getElementById('input-a').addEventListener('input', () => this.updatePreview('a'));
    document.getElementById('input-b').addEventListener('input', () => this.updatePreview('b'));

    // Swap
    document.getElementById('swap-btn').addEventListener('click', () => this.swap());

    // Operations
    document.querySelectorAll('.op-btn').forEach(btn => {
      btn.addEventListener('click', () => this.compute(btn.dataset.op));
    });

    // Result actions
    document.getElementById('use-as-a').addEventListener('click', () => this.useResultAs('a'));
    document.getElementById('use-as-b').addEventListener('click', () => this.useResultAs('b'));
  },

  setDegree(d) {
    this.m = d;

    // Update degree buttons
    document.querySelectorAll('#degree-btns button').forEach(btn => {
      btn.classList.toggle('active', parseInt(btn.dataset.degree) === d);
    });
    document.getElementById('degree-input').value = d;

    // Load default irreducible polynomial if available
    if (IRREDUCIBLE_DEFAULTS[d]) {
      this.irr = IRREDUCIBLE_DEFAULTS[d];
    } else {
      // For degrees without a default, set a placeholder (x^m + 1, which is likely reducible)
      // The user must provide a correct one
      this.irr = (1n << BigInt(d)) | 1n;
    }

    this.updateIrreducibleDisplay();
    this.updatePlaceholders();
    this.updatePreview('a');
    this.updatePreview('b');
    this.hideResults();
  },

  updateIrreducibleDisplay() {
    const input = document.getElementById('irr-input');
    const preview = document.getElementById('irr-preview');
    const error = document.getElementById('irr-error');

    input.value = polyStr(this.irr);
    preview.textContent = `Binary: ${toBin(this.irr)}  |  Hex: ${toHex(this.irr)}  |  Degree: ${degree(this.irr)}`;
    error.textContent = '';

    if (!IRREDUCIBLE_DEFAULTS[this.m]) {
      error.textContent = `No default for m=${this.m}. Please verify your irreducible polynomial is correct.`;
      error.style.color = 'var(--yellow)';
    }
  },

  onIrrInput() {
    const input = document.getElementById('irr-input');
    const preview = document.getElementById('irr-preview');
    const error = document.getElementById('irr-error');

    const val = parsePoly(input.value);

    if (val === null) {
      error.textContent = 'Invalid polynomial format.';
      error.style.color = 'var(--red)';
      preview.textContent = '';
      return;
    }

    const deg = degree(val);
    if (deg !== this.m) {
      error.textContent = `Degree is ${deg}, but must be ${this.m} for GF(2^${this.m}).`;
      error.style.color = 'var(--red)';
    } else {
      error.textContent = '';
    }

    this.irr = val;
    preview.textContent = `Binary: ${toBin(val)}  |  Hex: ${toHex(val)}  |  Degree: ${deg}`;
  },

  resetIrreducible() {
    if (IRREDUCIBLE_DEFAULTS[this.m]) {
      this.irr = IRREDUCIBLE_DEFAULTS[this.m];
    } else {
      this.irr = (1n << BigInt(this.m)) | 1n;
    }
    this.updateIrreducibleDisplay();
  },

  setFormat(fmt) {
    const inputA = document.getElementById('input-a');
    const inputB = document.getElementById('input-b');
    const valA = this.parseInput(inputA.value);
    const valB = this.parseInput(inputB.value);

    this.format = fmt;

    document.querySelectorAll('#format-toggle button').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.format === fmt);
    });

    // Re-display values in new format
    if (valA !== null && valA !== -1n && inputA.value.trim() !== '') {
      inputA.value = this.formatValue(valA);
    }
    if (valB !== null && valB !== -1n && inputB.value.trim() !== '') {
      inputB.value = this.formatValue(valB);
    }

    this.updatePlaceholders();
    this.updatePreview('a');
    this.updatePreview('b');
  },

  updatePlaceholders() {
    const a = document.getElementById('input-a');
    const b = document.getElementById('input-b');
    if (this.format === 'bin') {
      a.placeholder = `e.g. ${'1'.padEnd(this.m, '0')} (binary)`;
      b.placeholder = `e.g. ${'1'.padEnd(this.m, '0')} (binary)`;
    } else if (this.format === 'hex') {
      a.placeholder = `e.g. ${toHex((1n << BigInt(this.m)) - 1n)} (hex)`;
      b.placeholder = `e.g. ${toHex((1n << BigInt(this.m)) - 1n)} (hex)`;
    } else {
      a.placeholder = `e.g. x^${this.m - 1} + x + 1`;
      b.placeholder = `e.g. 3x^3 + 2x^2 + x + 1`;
    }
  },

  // Parse input based on current format. Returns BigInt or null (empty) or -1n (error).
  parseInput(str) {
    str = str.trim();
    if (str === '') return null;

    if (this.format === 'bin') {
      if (!/^[01]+$/.test(str)) return -1n;
      return BigInt('0b' + str);
    } else if (this.format === 'hex') {
      if (!/^[0-9a-fA-F]+$/.test(str)) return -1n;
      return BigInt('0x' + str);
    } else {
      const val = parsePoly(str);
      return val === null ? -1n : val;
    }
  },

  formatValue(val) {
    if (val === null || val === undefined || val < 0n) return '';
    if (this.format === 'bin') return toBin(val);
    if (this.format === 'hex') return toHex(val);
    return polyStr(val);
  },

  updatePreview(which) {
    const input = document.getElementById(`input-${which}`);
    const preview = document.getElementById(`preview-${which}`);
    const error = document.getElementById(`error-${which}`);
    const str = input.value.trim();

    error.textContent = '';

    if (str === '') {
      preview.textContent = 'Enter a value';
      preview.style.color = 'var(--text-muted)';
      return;
    }

    const val = this.parseInput(str);

    if (val === -1n) {
      preview.textContent = '';
      if (this.format === 'bin') error.textContent = 'Invalid: use only 0 and 1';
      else if (this.format === 'hex') error.textContent = 'Invalid: use only 0-9 and A-F';
      else error.textContent = 'Invalid polynomial. Use: x^5 + x + 1 or 3x5 + 2x2 + 1';
      return;
    }

    if (val === null) {
      preview.textContent = 'Enter a value';
      preview.style.color = 'var(--text-muted)';
      return;
    }

    // Show polynomial notation (or binary/hex if format is poly)
    if (this.format === 'poly') {
      preview.textContent = `Binary: ${toBin(val)}  |  Hex: ${toHex(val)}`;
    } else {
      preview.textContent = polyStr(val);
    }
    preview.style.color = 'var(--cyan)';

    // Warn if degree >= m (only for non-mod operations, but show it always as info)
    if (degree(val) >= this.m) {
      error.textContent = `Degree ${degree(val)} \u2265 m=${this.m}. Only valid for Mod Reduce.`;
    }
  },

  swap() {
    const inputA = document.getElementById('input-a');
    const inputB = document.getElementById('input-b');
    const tmp = inputA.value;
    inputA.value = inputB.value;
    inputB.value = tmp;
    this.updatePreview('a');
    this.updatePreview('b');
  },

  hideResults() {
    document.getElementById('result-section').classList.add('hidden');
    document.getElementById('steps-section').classList.add('hidden');
  },

  validate(a, b, op) {
    const singleOps = ['mod', 'inv'];
    const needsB = !singleOps.includes(op);

    if (a === null || a === -1n) {
      return 'Polynomial A is required and must be valid.';
    }
    if (needsB && (b === null || b === -1n)) {
      return 'Polynomial B is required and must be valid.';
    }

    // Validate irreducible polynomial
    if (degree(this.irr) !== this.m) {
      return `Irreducible polynomial has degree ${degree(this.irr)}, expected ${this.m}. Fix it above.`;
    }

    // For mod reduction, allow any degree
    if (op === 'mod') return null;

    // For other ops, inputs must be field elements (degree < m)
    if (degree(a) >= this.m) {
      return `A has degree ${degree(a)} but must be < ${this.m}. Use Mod Reduce first.`;
    }
    if (needsB && degree(b) >= this.m) {
      return `B has degree ${degree(b)} but must be < ${this.m}. Use Mod Reduce first.`;
    }

    return null;
  },

  compute(op) {
    const a = this.parseInput(document.getElementById('input-a').value);
    const b = this.parseInput(document.getElementById('input-b').value);

    const err = this.validate(a, b, op);
    if (err) {
      this.showError(err);
      return;
    }

    let outcome;
    switch (op) {
      case 'add': outcome = opAdd(a, b, this.m, this.irr); break;
      case 'sub': outcome = opSub(a, b, this.m, this.irr); break;
      case 'mul': outcome = opMul(a, b, this.m, this.irr); break;
      case 'div': outcome = opDiv(a, b, this.m, this.irr); break;
      case 'mod': outcome = opMod(a, this.m, this.irr); break;
      case 'inv': outcome = opInverse(a, this.m, this.irr); break;
    }

    this.lastResult = outcome.result;

    if (outcome.result !== null) {
      this.showResult(outcome.result, op);
    } else {
      const errStep = outcome.steps.find(s => s.error);
      this.showError(errStep ? errStep.text : 'Operation failed.');
    }

    this.showSteps(outcome.steps);
  },

  showResult(val, op) {
    const section = document.getElementById('result-section');
    const title = document.getElementById('result-title');
    const valEl = document.getElementById('result-value');
    const polyEl = document.getElementById('result-poly');
    const altEl = document.getElementById('result-alt');

    section.classList.remove('hidden', 'error');
    section.style.animation = 'none';
    section.offsetHeight;
    section.style.animation = '';

    const opNames = {
      add: 'Addition Result',
      sub: 'Subtraction Result',
      mul: 'Multiplication Result',
      div: 'Division Result',
      mod: 'Modulo Reduction Result',
      inv: 'Multiplicative Inverse'
    };
    title.textContent = opNames[op] || 'Result';

    // Primary display based on format
    if (this.format === 'bin') {
      valEl.textContent = toBin(val, this.m);
    } else if (this.format === 'hex') {
      valEl.textContent = toHex(val);
    } else {
      valEl.textContent = polyStr(val);
    }

    // Polynomial notation (always shown)
    polyEl.textContent = this.format === 'poly' ? '' : polyStr(val);

    // Alternate representations
    const parts = [];
    if (this.format !== 'bin') parts.push(`Bin: ${toBin(val)}`);
    if (this.format !== 'hex') parts.push(`Hex: ${toHex(val)}`);
    if (this.format === 'poly') parts.push(`Decimal: ${val.toString()}`);
    altEl.textContent = parts.join('  |  ');
  },

  showError(msg) {
    const section = document.getElementById('result-section');
    const title = document.getElementById('result-title');
    const valEl = document.getElementById('result-value');
    const polyEl = document.getElementById('result-poly');
    const altEl = document.getElementById('result-alt');

    section.classList.remove('hidden');
    section.classList.add('error');
    section.style.animation = 'none';
    section.offsetHeight;
    section.style.animation = '';

    title.textContent = 'Error';
    valEl.textContent = msg;
    polyEl.textContent = '';
    altEl.textContent = '';
  },

  showSteps(steps) {
    const section = document.getElementById('steps-section');
    const container = document.getElementById('steps-container');

    section.classList.remove('hidden');
    container.innerHTML = '';

    for (const step of steps) {
      const div = document.createElement('div');
      div.className = 'step-item';
      if (step.highlight) div.classList.add('highlight');
      if (step.error) div.classList.add('error');
      if (step.section) div.classList.add('section-header');

      div.innerHTML =
        `<span class="step-label">${step.label}</span>` +
        `<span class="step-text">${step.text}</span>`;
      container.appendChild(div);
    }

    section.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  },

  useResultAs(which) {
    if (this.lastResult === null) return;
    const input = document.getElementById(`input-${which}`);
    input.value = this.formatValue(this.lastResult);
    this.updatePreview(which);
  }
};

// ===================== INIT =====================

document.addEventListener('DOMContentLoaded', () => App.init());
