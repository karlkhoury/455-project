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

const STANDARD_LARGE_POLYS = {
  163: [163, 7, 6, 3, 0],
  233: [233, 74, 0],
  283: [283, 12, 7, 5, 0],
  409: [409, 87, 0],
  571: [571, 10, 5, 2, 0],
};

const SMALL_EXTRA_CANDIDATES = {
  2: [7],
  3: [11, 13],
  4: [19, 25, 31],
  5: [37, 41, 47, 55, 59, 61],
  6: [67, 73, 87, 91, 97, 103, 109, 115, 117],
  7: [131, 137, 143, 145, 157, 167, 171, 185, 191, 193, 203, 211, 213, 229, 239, 241, 247, 253],
  8: [283, 285, 299, 301, 313, 319, 333, 351, 355, 357, 361, 369, 375, 379, 391, 395, 397, 415, 419, 425, 433, 445, 451, 463, 471, 477, 487, 499, 501, 505],
  16: [0x1100B],
};

const CODING_BYTE_DEGREES = [4, 8, 16, 32, 64];
const CURVE_FIELD_DEGREES = [163, 233, 239, 283, 409, 571];
const BCH_RS_DEGREES = [7, 8, 9, 10, 12, 13];

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

function splitPolynomialLine(text) {
  const markers = ['  |  Hex:', '  |  Degree:', ' | Hex:'];
  let end = text.length;
  for (const marker of markers) {
    const idx = text.indexOf(marker);
    if (idx !== -1) end = Math.min(end, idx);
  }
  return [text.slice(0, end), text.slice(end)];
}

function setPolynomialMixedText(element, text) {
  element.textContent = '';
  const [poly, rest] = splitPolynomialLine(text);
  const polySpan = document.createElement('span');
  polySpan.className = 'poly-font';
  polySpan.textContent = poly;
  element.appendChild(polySpan);
  if (rest) element.appendChild(document.createTextNode(rest));
}

function digitsToSuperscript(str) {
  return String(str).split('').map(d => SUP_CHARS[parseInt(d)] || d).join('');
}

function normalizeSuperscriptNotation(str) {
  return str.replace(/\^(\d+)/g, (_, digits) => digitsToSuperscript(digits));
}

function formatFormulaDisplay(str) {
  return normalizeSuperscriptNotation(str)
    .replace(/\bxor\b/gi, '\u2295')
    .replace(/\*/g, '\u00D7')
    .replace(/\//g, '\u00F7');
}

function looksLikeMathText(text) {
  return /(^|[^a-zA-Z])x($|[^a-zA-Z])|[⁰¹²³⁴⁵⁶⁷⁸⁹⊕×÷·≡≥≤]|inv\s*\(/i.test(text);
}

function looksLikeBinaryText(text) {
  return /^[01\s⊕=]+$/.test(text.trim());
}

function renderStepText(element, text, label) {
  element.textContent = '';

  if (looksLikeBinaryText(text) || /^Binary/i.test(label)) {
    element.textContent = text;
    return;
  }

  const binaryThenMath = text.match(/^([01\s]+=\s*)(.+)$/);
  if (binaryThenMath && looksLikeMathText(binaryThenMath[2])) {
    element.appendChild(document.createTextNode(binaryThenMath[1]));
    const math = document.createElement('span');
    math.className = 'math-step-text';
    math.textContent = binaryThenMath[2];
    element.appendChild(math);
    return;
  }

  element.textContent = text;
  if (
    looksLikeMathText(text) ||
    /formula|operation|variable|result/i.test(label)
  ) {
    element.classList.add('math-step-text');
  }
}

function insertAtCursor(input, text) {
  const start = input.selectionStart;
  const end = input.selectionEnd;
  input.value = input.value.slice(0, start) + text + input.value.slice(end);
  const cursor = start + text.length;
  input.setSelectionRange(cursor, cursor);
  input.dispatchEvent(new Event('input', { bubbles: true }));
}

function compactPreview(label, value, maxLen = 10) {
  return value.length > maxLen ? `${label}: ${value.slice(0, maxLen)}...` : `${label}: ${value}`;
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

function polyFromExponents(exponents) {
  let p = 0n;
  for (const e of exponents) p |= (1n << BigInt(e));
  return p;
}

function naturalWidth(...values) {
  let max = 1;
  for (const v of values) {
    if (typeof v !== 'bigint') continue;
    const w = v === 0n ? 1 : v.toString(2).length;
    if (w > max) max = w;
  }
  return max;
}

function primeDivisors(n) {
  const result = [];
  let x = n;
  for (let d = 2; d * d <= x; d++) {
    if (x % d === 0) {
      result.push(d);
      while (x % d === 0) x = Math.floor(x / d);
    }
  }
  if (x > 1) result.push(x);
  return result;
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

function polyGcd(a, b) {
  let x = a, y = b;
  while (y !== 0n) {
    const div = polyDivMod(x, y);
    if (!div) return x;
    x = y;
    y = div[1];
  }
  return x;
}

function squareMod(a, mod) {
  let squared = 0n;
  let p = a;
  let i = 0n;
  while (p > 0n) {
    if (p & 1n) squared |= (1n << (2n * i));
    p >>= 1n;
    i++;
  }
  return reduceSimple(squared, mod);
}

function frobeniusX(iterations, mod) {
  let x = 2n;
  for (let i = 0; i < iterations; i++) {
    x = squareMod(x, mod);
  }
  return x;
}

function isIrreducibleRabin(f) {
  const m = degree(f);
  if (m <= 0) return false;
  if ((f & 1n) === 0n) return false;

  const x = 2n;
  for (const q of primeDivisors(m)) {
    const test = frobeniusX(Math.floor(m / q), f) ^ x;
    if (polyGcd(test, f) !== 1n) return false;
  }

  return frobeniusX(m, f) === x;
}

function validateModulusPolynomial(f, m) {
  if (f === null) return 'Invalid polynomial format.';
  if (degree(f) !== m) return `Degree is ${degree(f)}, but must be exactly ${m}.`;
  if ((f & (1n << BigInt(m))) === 0n) return 'Leading coefficient must be 1.';
  if ((f & 1n) === 0n) return 'Constant term must be 1.';
  if (!isIrreducibleRabin(f)) return 'Polynomial is reducible over GF(2).';
  return null;
}

function makeModulusOption(poly, status) {
  return { poly, status, selected: false };
}

function searchSparseIrreducible(m) {
  if (m % 8 !== 0) {
    for (let k = 1; k <= Math.floor(m / 2); k++) {
      const p = polyFromExponents([m, k, 0]);
      if (isIrreducibleRabin(p)) return makeModulusOption(p, 'generated trinomial');
    }
  }

  const limits = [25, 50, 80, Math.min(128, m - 1)];
  for (const limit of limits) {
    const top = Math.min(limit, m - 1);
    for (let c = 1; c <= top - 2; c++) {
      for (let b = c + 1; b <= top - 1; b++) {
        for (let a = b + 1; a <= top; a++) {
          const p = polyFromExponents([m, a, b, c, 0]);
          if (isIrreducibleRabin(p)) return makeModulusOption(p, 'generated pentanomial');
        }
      }
    }
  }

  if (m <= 80) {
    const middle = Math.floor(m / 2);
    for (let mask = 1; mask < 1 << Math.min(m - 1, 20); mask += 2) {
      let p = (1n << BigInt(m)) | 1n;
      for (let i = 1; i <= Math.min(m - 1, 20); i++) {
        if (mask & (1 << (i - 1))) p |= (1n << BigInt((middle + i) % m || i));
      }
      if (isIrreducibleRabin(p)) return makeModulusOption(p, 'generated');
    }
  }

  return null;
}

// ===================== OPERATIONS WITH STEPS =====================

function opAdd(a, b, m, irr) {
  const steps = [];
  const result = a ^ b;
  const w = naturalWidth(a, b, result);
  steps.push({ label: 'Operation', text: `${polyStr(a)}  \u2295  ${polyStr(b)}`, section: true });
  steps.push({ label: 'Binary XOR', text: `${toBin(a, w)} \u2295 ${toBin(b, w)}` });
  steps.push({ label: 'Result', text: `${toBin(result, w)}  =  ${polyStr(result)}`, highlight: true });
  return { result, steps };
}

function opSub(a, b, m, irr) {
  const steps = [];
  const result = a ^ b;
  const w = naturalWidth(a, b, result);
  steps.push({ label: 'Operation', text: `${polyStr(a)}  \u2296  ${polyStr(b)}`, section: true });
  steps.push({ label: 'Note', text: 'In GF(2), subtraction is identical to addition (XOR)', section: true });
  steps.push({ label: 'Binary XOR', text: `${toBin(a, w)} \u2295 ${toBin(b, w)}` });
  steps.push({ label: 'Result', text: `${toBin(result, w)}  =  ${polyStr(result)}`, highlight: true });
  return { result, steps };
}

function opMod(a, m, irr) {
  const steps = [];
  steps.push({ label: 'Operation', text: `Reduce ${polyStr(a)} mod ${polyStr(irr)}`, section: true });
  steps.push({ label: 'Input', text: `${toBin(a)} (degree ${degree(a)})` });

  if (degree(a) < m) {
    steps.push({ label: 'No reduction', text: `Degree ${degree(a)} < ${m}, already in the field` });
    steps.push({ label: 'Result', text: `${toBin(a)}  =  ${polyStr(a)}`, highlight: true });
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

  steps.push({ label: 'Result', text: `${toBin(p)}  =  ${polyStr(p)}`, highlight: true });
  return { result: p, steps };
}

function opMul(a, b, m, irr) {
  // Compute partial products and raw product first so we know display widths
  const _operandW = naturalWidth(a, b);
  let _product = 0n;
  const _partials = [];
  let _bb = b;
  let _i = 0;
  while (_bb > 0n) {
    if (_bb & 1n) {
      const _partial = a << BigInt(_i);
      _partials.push({ i: _i, partial: _partial });
      _product ^= _partial;
    }
    _bb >>= 1n;
    _i++;
  }
  const _mulW = naturalWidth(_product, a, b, ..._partials.map(p => p.partial));

  const steps = [];
  steps.push({ label: 'Operation', text: `(${polyStr(a)}) \u00D7 (${polyStr(b)})`, section: true });
  steps.push({ label: 'Step 1', text: 'Polynomial multiplication (shift-and-XOR)', section: true });

  for (const { i: _bi, partial: _partial } of _partials) {
    steps.push({
      label: `Bit ${_bi} of B = 1`,
      text: `A « ${_bi} = ${toBin(_partial, _mulW)}  (${polyStr(_partial)})`
    });
  }

  steps.push({ label: 'Raw product', text: `${toBin(_product, _mulW)}  =  ${polyStr(_product)}` });

  if (degree(_product) >= m) {
    steps.push({ label: 'Step 2', text: `Reduce mod ${polyStr(irr)}`, section: true });
    let p = _product;
    let stepNum = 1;
    while (p !== 0n && degree(p) >= m) {
      const shift = degree(p) - m;
      const shifted = irr << BigInt(shift);
      const prev = p;
      p ^= shifted;
      const rowW = naturalWidth(prev, shifted, p);
      steps.push({
        label: `Reduce ${stepNum}`,
        text: `${toBin(prev, rowW)} ⊕ ${toBin(shifted, rowW)} = ${toBin(p, rowW)}`
      });
      stepNum++;
    }
    const finalW = Math.max(_operandW, naturalWidth(p));
    steps.push({ label: 'Result', text: `${toBin(p, finalW)}  =  ${polyStr(p)}`, highlight: true });
    return { result: p, steps };
  }

  steps.push({ label: 'No reduction', text: `Degree ${degree(_product)} < ${m}` });
  const _finalW2 = Math.max(_operandW, naturalWidth(_product));
  steps.push({ label: 'Result', text: `${toBin(_product, _finalW2)}  =  ${polyStr(_product)}`, highlight: true });
  return { result: _product, steps };
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

function opPower(base, exp, m, irr) {
  const steps = [];
  steps.push({ label: 'Operation', text: `(${polyStr(base)})^${exp} in GF(2${sup(m)})`, section: true });

  if (!Number.isFinite(exp) || exp < 0) {
    steps.push({ label: 'Error', text: 'Exponent must be a non-negative integer.', error: true });
    return { result: null, steps };
  }

  if (exp === 0) {
    steps.push({ label: 'Note', text: 'Any element raised to 0 is 1.' });
    steps.push({ label: 'Result', text: `1  =  1`, highlight: true });
    return { result: 1n, steps };
  }

  if (base === 0n) {
    steps.push({ label: 'Note', text: '0 raised to any positive exponent is 0.' });
    steps.push({ label: 'Result', text: `0  =  0`, highlight: true });
    return { result: 0n, steps };
  }

  if (exp === 1) {
    steps.push({ label: 'Note', text: 'Exponent 1 returns the base unchanged.' });
    steps.push({ label: 'Result', text: `${toBin(base)}  =  ${polyStr(base)}`, highlight: true });
    return { result: base, steps };
  }

  steps.push({ label: 'Method', text: 'Square-and-multiply (binary exponentiation)', section: true });
  steps.push({ label: 'Exponent', text: `${exp} = ${exp.toString(2)} (binary, scanned LSB → MSB)` });

  let result = 1n;
  let acc = base;
  let n = exp;
  let bit = 0;

  while (n > 0) {
    if (n & 1) {
      const before = result;
      result = reduceSimple(mulRaw(result, acc), irr);
      steps.push({
        label: `Bit ${bit} = 1`,
        text: `result ← (${polyStr(before)}) × (${polyStr(acc)}) mod p = ${polyStr(result)}`
      });
    }
    n >>>= 1;
    if (n > 0) {
      const before = acc;
      acc = reduceSimple(mulRaw(acc, acc), irr);
      steps.push({
        label: 'Square',
        text: `acc ← (${polyStr(before)})² mod p = ${polyStr(acc)}`
      });
    }
    bit++;
  }

  steps.push({ label: 'Result', text: `${toBin(result)}  =  ${polyStr(result)}`, highlight: true });
  return { result, steps };
}

// ===================== FORMULA PARSER =====================

function isExponentContext(tokens) {
  for (let k = tokens.length - 1; k >= 0; k--) {
    if (tokens[k].type === '^') return true;
    if (tokens[k].type !== '(') return false;
  }
  return false;
}

function tokenizeFormula(str) {
  const tokens = [];
  let i = 0;

  while (i < str.length) {
    const ch = str[i];
    const afterCaret = isExponentContext(tokens);

    if (/\s/.test(ch)) {
      i++;
      continue;
    }

    if (ch === '^') {
      tokens.push({ type: '^', value: '^' });
      i++;
      continue;
    }

    if ('()+-'.includes(ch)) {
      tokens.push({ type: ch, value: ch });
      i++;
      continue;
    }

    if (ch === '*' || ch === '\u00D7') {
      tokens.push({ type: '*', value: ch });
      i++;
      continue;
    }

    if (ch === '/' || ch === '\u00F7') {
      tokens.push({ type: '/', value: ch });
      i++;
      continue;
    }

    if (ch === '\u2295') {
      tokens.push({ type: 'xor', value: '\u2295' });
      i++;
      continue;
    }

    if (ch === '[') {
      const end = str.indexOf(']', i + 1);
      if (end === -1) throw new Error('Missing closing ] for polynomial literal.');
      tokens.push({ type: 'literal', value: str.slice(i + 1, end) });
      i = end + 1;
      continue;
    }

    if (str.slice(i, i + 2).toLowerCase() === '0b') {
      let j = i + 2;
      while (j < str.length && /[01]/.test(str[j])) j++;
      if (j === i + 2) throw new Error('Binary literal must contain at least one bit.');
      tokens.push({ type: 'number', value: str.slice(i, j) });
      i = j;
      continue;
    }

    if (str.slice(i, i + 2).toLowerCase() === '0x') {
      let j = i + 2;
      while (j < str.length && /[0-9a-fA-F]/.test(str[j])) j++;
      if (j === i + 2) throw new Error('Hex literal must contain at least one digit.');
      tokens.push({ type: 'number', value: str.slice(i, j) });
      i = j;
      continue;
    }

    if (/[0-9]/.test(ch)) {
      let j = i;
      while (j < str.length && /[0-9]/.test(str[j])) j++;
      const num = str.slice(i, j);
      if (afterCaret) {
        tokens.push({ type: 'intnum', value: num });
      } else if (/^[01]+$/.test(num)) {
        tokens.push({ type: 'number', value: num });
      } else {
        throw new Error(`"${num}" is not a valid binary literal. Use 0b/0x prefixes or [polynomial] notation.`);
      }
      i = j;
      continue;
    }

    if (/[a-zA-Z]/.test(ch)) {
      let j = i;
      while (j < str.length && /[a-zA-Z0-9_]/.test(str[j])) j++;
      const word = str.slice(i, j);
      const lower = word.toLowerCase();
      if (lower === 'xor' || lower === 'inv') {
        tokens.push({ type: lower, value: lower });
      } else if (/^[A-Z][A-Z0-9_]*$/.test(word.toUpperCase())) {
        tokens.push({ type: 'var', value: word.toUpperCase() });
      } else {
        throw new Error(`Unknown identifier "${word}". Use a variable name, xor, or inv(...).`);
      }
      i = j;
      continue;
    }

    throw new Error(`Unexpected character "${ch}".`);
  }

  return tokens;
}

function FormulaParser(tokens, variables, app) {
  this.tokens = tokens;
  this.pos = 0;
  this.variables = variables;
  this.app = app;
  this.steps = [];
}

FormulaParser.prototype.peek = function() {
  return this.tokens[this.pos];
};

FormulaParser.prototype.consume = function(type) {
  const token = this.peek();
  if (!token || token.type !== type) return null;
  this.pos++;
  return token;
};

FormulaParser.prototype.expect = function(type, message) {
  const token = this.consume(type);
  if (!token) throw new Error(message);
  return token;
};

FormulaParser.prototype.ensureFieldElement = function(node) {
  if (degree(node.value) >= this.app.m) {
    throw new Error(`${node.repr} has degree ${degree(node.value)} but must be < ${this.app.m}. Reduce it first.`);
  }
};

FormulaParser.prototype.parse = function() {
  const result = this.parseExpression();
  if (this.peek()) {
    throw new Error(`Unexpected token "${this.peek().value}".`);
  }
  return result;
};

FormulaParser.prototype.parseExpression = function() {
  let node = this.parseTerm();

  while (this.peek() && ['+', '-', 'xor'].includes(this.peek().type)) {
    const op = this.peek().type;
    this.pos++;
    const right = this.parseTerm();
    node = this.applyBinary(op, node, right);
  }

  return node;
};

FormulaParser.prototype.parseTerm = function() {
  let node = this.parsePower();

  while (this.peek() && ['*', '/'].includes(this.peek().type)) {
    const op = this.peek().type;
    this.pos++;
    const right = this.parsePower();
    node = this.applyBinary(op, node, right);
  }

  return node;
};

FormulaParser.prototype.parsePower = function() {
  let node = this.parseUnary();

  while (this.peek() && this.peek().type === '^') {
    this.pos++;
    let expValue;
    let expRepr;

    if (this.peek() && this.peek().type === '(') {
      this.pos++;
      const intToken = this.expect('intnum', 'Exponent must be a non-negative integer (e.g. A^5).');
      this.expect(')', 'Expected closing ) after exponent.');
      expValue = parseInt(intToken.value, 10);
      expRepr = `(${intToken.value})`;
    } else {
      const intToken = this.consume('intnum');
      if (!intToken) throw new Error('Exponent must be a non-negative integer (e.g. A^5).');
      expValue = parseInt(intToken.value, 10);
      expRepr = intToken.value;
    }

    if (!Number.isFinite(expValue) || expValue < 0) {
      throw new Error(`Invalid exponent: ${expRepr}.`);
    }
    if (expValue > 1000000) {
      throw new Error(`Exponent ${expValue} is too large; please use a value below 10^6.`);
    }

    this.ensureFieldElement(node);
    this.steps.push({ label: 'Formula Step', text: `${node.repr}^${expRepr}`, section: true });
    const outcome = opPower(node.value, expValue, this.app.m, this.app.irr);
    this.steps.push(...outcome.steps);
    if (outcome.result === null) {
      const errStep = outcome.steps.find(s => s.error);
      throw new Error(errStep ? errStep.text : 'Power evaluation failed.');
    }
    node = { value: outcome.result, repr: `(${node.repr}^${expRepr})` };
  }

  return node;
};

FormulaParser.prototype.parseUnary = function() {
  if (this.consume('inv')) {
    this.expect('(', 'Expected ( after inv.');
    const inner = this.parseExpression();
    this.expect(')', 'Expected ) after inv argument.');
    this.ensureFieldElement(inner);

    this.steps.push({ label: 'Formula Step', text: `inv(${inner.repr})`, section: true });
    const outcome = opInverse(inner.value, this.app.m, this.app.irr);
    this.steps.push(...outcome.steps);
    if (outcome.result === null) {
      const errStep = outcome.steps.find(s => s.error);
      throw new Error(errStep ? errStep.text : 'Inverse failed.');
    }
    return { value: outcome.result, repr: `inv(${inner.repr})` };
  }

  return this.parsePrimary();
};

FormulaParser.prototype.parsePrimary = function() {
  const token = this.peek();
  if (!token) throw new Error('Formula ended too early.');

  if (this.consume('(')) {
    const node = this.parseExpression();
    this.expect(')', 'Expected closing ).');
    return { value: node.value, repr: `(${node.repr})` };
  }

  if (token.type === 'var') {
    this.pos++;
    const entry = this.variables[token.value];
    if (!entry) throw new Error(`Variable ${token.value} is empty or invalid.`);
    return { value: entry.value, repr: token.value };
  }

  if (token.type === 'number') {
    this.pos++;
    let value;
    if (token.value.toLowerCase().startsWith('0x')) {
      value = BigInt(token.value);
    } else if (token.value.toLowerCase().startsWith('0b')) {
      value = BigInt(token.value);
    } else {
      value = BigInt('0b' + token.value);
    }
    return { value, repr: token.value };
  }

  if (token.type === 'literal') {
    this.pos++;
    const value = parsePoly(token.value);
    if (value === null) throw new Error(`Invalid polynomial literal [${token.value}].`);
    return { value, repr: `[${polyStr(value)}]` };
  }

  throw new Error(`Unexpected token "${token.value}".`);
};

FormulaParser.prototype.applyBinary = function(op, left, right) {
  this.ensureFieldElement(left);
  this.ensureFieldElement(right);

  const symbol = op === '*' ? '\u00D7' : op === '/' ? '\u00F7' : '\u2295';
  this.steps.push({ label: 'Formula Step', text: `${left.repr} ${symbol} ${right.repr}`, section: true });

  let outcome;
  if (op === '+' || op === '-' || op === 'xor') {
    outcome = op === '-' ? opSub(left.value, right.value, this.app.m, this.app.irr)
                         : opAdd(left.value, right.value, this.app.m, this.app.irr);
  } else if (op === '*') {
    outcome = opMul(left.value, right.value, this.app.m, this.app.irr);
  } else {
    outcome = opDiv(left.value, right.value, this.app.m, this.app.irr);
  }

  this.steps.push(...outcome.steps);
  if (outcome.result === null) {
    const errStep = outcome.steps.find(s => s.error);
    throw new Error(errStep ? errStep.text : 'Formula operation failed.');
  }

  return { value: outcome.result, repr: `(${left.repr} ${symbol} ${right.repr})` };
};


// ===================== FIELD-STATS HELPERS =====================

function primeFactorsBigInt(n) {
  // Returns array of [prime, exponent] for small/medium n.
  // Caps trial division at ~1e7. For larger leftovers, returns last factor as-is.
  const factors = [];
  let x = n;
  let d = 2n;
  while (d * d <= x && d < 10000000n) {
    if (x % d === 0n) {
      let e = 0;
      while (x % d === 0n) { x = x / d; e++; }
      factors.push([d, e]);
    }
    d++;
  }
  if (x > 1n) factors.push([x, 1]);
  return factors;
}

function powModPoly(base, exp, mod) {
  // Compute base^exp mod p in GF(2)[x] / (mod) using square-and-multiply.
  let result = 1n;
  let acc = base;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = reduceSimple(mulRaw(result, acc), mod);
    acc = reduceSimple(mulRaw(acc, acc), mod);
    e >>= 1n;
  }
  return result;
}

function findPrimitiveElement(m, irr, factors) {
  // Smallest g such that g has order 2^m - 1 in GF(2^m) mod irr.
  // Returns null if exhaustive search exceeds the field size.
  const N = (1n << BigInt(m)) - 1n;
  const facList = factors || primeFactorsBigInt(N);
  const upper = (1n << BigInt(m));
  for (let g = 2n; g < upper; g++) {
    let isPrim = true;
    for (const [p] of facList) {
      const t = powModPoly(g, N / p, irr);
      if (t === 1n) { isPrim = false; break; }
    }
    if (isPrim) return g;
  }
  return null;
}

function orderOfX(m, irr, factors) {
  // Smallest k > 0 such that x^k ≡ 1 (mod irr). k must divide 2^m - 1.
  // Use the divisor approach: start with N = 2^m - 1, for each prime factor p,
  // while x^(N/p) == 1 in field, divide N by p.
  const N = (1n << BigInt(m)) - 1n;
  let order = N;
  const facList = factors || primeFactorsBigInt(N);
  for (const [p] of facList) {
    while (order % p === 0n) {
      const candidate = order / p;
      const r = powModPoly(2n, candidate, irr); // 2n represents x
      if (r === 1n) order = candidate;
      else break;
    }
  }
  return order;
}

// ===================== UI CONTROLLER =====================

const HISTORY_STORAGE_KEY = 'gf2m-calc-history-v1';
const HISTORY_MAX_ENTRIES = 50;
const THEME_STORAGE_KEY = 'gf2m-calc-theme-v1';

const App = {
  m: 8,
  resultFormat: 'bin',
  irr: IRREDUCIBLE_DEFAULTS[8],
  modulusOptions: [],
  lastResult: null,
  lastDisplayedResult: '',
  formulaHistory: [''],
  formulaHistoryIndex: 0,
  recordingFormulaHistory: true,
  variableNames: [],
  nextVariableCode: 'A'.charCodeAt(0),
  history: [],
  showingBitViz: false,

  init() {
    this.applyStoredTheme();
    this.buildDegreeSelectors();
    this.addVariable('A');
    this.addVariable('B');
    this.addVariable('C');
    this.bindEvents();
    this.bindCollapsibles();
    this.bindKeyboardShortcuts();
    this.bindThemeToggle();
    this.buildModulusOptions();
    this.updateIrreducibleDisplay();
    this.updatePlaceholders();
    this.loadHistory();
    this.renderHistory();
    this.loadPinned();
    this.renderPinned();
    this.bindConverter();
    this.bindCommandPalette();
    this.bindPlaybackControls();
    this.bindExportModal();
    this.bindStickyChip();
    this.renderFieldStats();
    this.renderFieldTables();
    const shareBtn = document.getElementById('workspace-share');
    if (shareBtn) shareBtn.addEventListener('click', () => this.shareWorkspace());
    // Restore from URL hash if present (after default init so DOM exists)
    if (window.location.hash && window.location.hash.startsWith('#s=')) {
      try { this.loadFromUrlHash(); } catch (e) { /* ignore */ }
    }
  },

  applyStoredTheme() {
    let theme = null;
    try {
      theme = localStorage.getItem(THEME_STORAGE_KEY);
    } catch (e) { /* ignore */ }
    if (theme !== 'light' && theme !== 'dark') {
      theme = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches
        ? 'light'
        : 'dark';
    }
    this.setTheme(theme);
  },

  setTheme(theme) {
    if (theme === 'light') {
      document.documentElement.setAttribute('data-theme', 'light');
    } else {
      document.documentElement.removeAttribute('data-theme');
    }
    try { localStorage.setItem(THEME_STORAGE_KEY, theme); } catch (e) { /* ignore */ }
  },

  bindThemeToggle() {
    const btn = document.getElementById('theme-toggle');
    if (!btn) return;
    btn.addEventListener('click', () => {
      const current = document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
      this.setTheme(current === 'light' ? 'dark' : 'light');
    });
  },

  buildDegreeSelectors() {
    const select = document.getElementById('degree-select');
    const custom = document.createElement('option');
    custom.value = 'custom';
    custom.textContent = 'Custom...';
    select.appendChild(custom);

    this.appendDegreeGroup(select, 'Coding & bytes', CODING_BYTE_DEGREES);
    this.appendDegreeGroup(select, 'ECC binary fields', CURVE_FIELD_DEGREES);
    this.appendDegreeGroup(select, 'BCH / RS codes', BCH_RS_DEGREES);
    select.value = String(this.m);
  },

  appendDegreeGroup(select, label, degrees) {
    const group = document.createElement('optgroup');
    group.label = label;
    for (const d of degrees) {
      const option = document.createElement('option');
      option.value = d;
      option.textContent = `m = ${d}`;
      group.appendChild(option);
    }
    select.appendChild(group);
  },

  bindEvents() {
    // Degree selectors
    document.getElementById('degree-select').addEventListener('change', event => {
      if (event.target.value === 'custom') {
        document.getElementById('degree-input').classList.remove('hidden');
        document.getElementById('degree-input').focus();
      } else {
        document.getElementById('degree-input').classList.add('hidden');
        this.setDegree(parseInt(event.target.value));
      }
    });

    const degInput = document.getElementById('degree-input');
    degInput.addEventListener('change', () => {
      let val = parseInt(degInput.value);
      if (isNaN(val) || val < 2) val = 2;
      if (val > 571) val = 571;
      degInput.value = val;
      this.setDegree(val);
    });

    // Irreducible polynomial input
    document.getElementById('irr-input').addEventListener('input', () => this.onIrrInput());
    this.bindPolynomialTyping(document.getElementById('irr-input'), () => true);
    document.getElementById('irr-reset').addEventListener('click', () => this.resetIrreducible());
    document.getElementById('irr-custom').addEventListener('click', () => this.useCustomModulus());
    document.getElementById('modulus-dropdown-btn').addEventListener('click', () => {
      document.getElementById('modulus-dropdown-menu').classList.toggle('hidden');
    });
    document.addEventListener('click', event => {
      if (!document.getElementById('modulus-dropdown').contains(event.target)) {
        document.getElementById('modulus-dropdown-menu').classList.add('hidden');
      }
    });

    // Formula variables
    document.getElementById('add-variable').addEventListener('click', () => this.addVariable());

    // Formula constructor
    document.getElementById('formula-input').addEventListener('input', () => this.onFormulaInput());
    document.getElementById('formula-eval').addEventListener('click', () => this.computeFormula());
    document.getElementById('formula-clear').addEventListener('click', () => this.clearFormula());
    document.getElementById('formula-undo').addEventListener('click', () => this.undoFormula());
    document.getElementById('formula-redo').addEventListener('click', () => this.redoFormula());
    document.getElementById('formula-paste').addEventListener('click', () => this.pasteFormula());
    document.querySelectorAll('#result-format-toggle button').forEach(btn => {
      btn.addEventListener('click', () => this.setResultFormat(btn.dataset.format));
    });

    // Result actions
    document.getElementById('copy-result').addEventListener('click', () => this.copyResult());
    document.getElementById('use-as-var').addEventListener('click', () => this.useResultAsVariable());
    document.getElementById('toggle-bit-viz').addEventListener('click', () => this.toggleBitViz());
    const pinBtn = document.getElementById('pin-result');
    if (pinBtn) pinBtn.addEventListener('click', () => this.pinCurrentResult());
    const expBtn = document.getElementById('export-result');
    if (expBtn) expBtn.addEventListener('click', () => this.openExportModal());
    const pinClear = document.getElementById('pinned-clear');
    if (pinClear) pinClear.addEventListener('click', () => this.clearPinned());

    // Workspace import/export
    document.getElementById('workspace-export').addEventListener('click', () => this.exportWorkspace());
    document.getElementById('workspace-import').addEventListener('click', () => {
      document.getElementById('workspace-file-input').click();
    });
    document.getElementById('workspace-file-input').addEventListener('change', event => {
      const file = event.target.files && event.target.files[0];
      if (file) this.importWorkspaceFile(file);
      event.target.value = '';
    });

    // History
    document.getElementById('history-clear').addEventListener('click', () => this.clearHistory());
  },

  setDegree(d) {
    this.m = d;

    const select = document.getElementById('degree-select');
    const knownDegrees = [...CODING_BYTE_DEGREES, ...CURVE_FIELD_DEGREES, ...BCH_RS_DEGREES];
    select.value = knownDegrees.includes(d) ? String(d) : 'custom';
    document.getElementById('degree-input').classList.toggle('hidden', select.value !== 'custom');
    document.getElementById('degree-input').value = d;

    this.buildModulusOptions();
    this.updateIrreducibleDisplay();
    this.updatePlaceholders();
    for (const name of this.variableNames) this.updateVariablePreview(name);
    this.updateFormulaPreview();
    this.hideResults();
    this.renderFieldStats();
    this.renderFieldTables();
  },

  updateIrreducibleDisplay() {
    const input = document.getElementById('irr-input');
    const preview = document.getElementById('irr-preview');
    const error = document.getElementById('irr-error');
    const status = this.selectedModulusStatus();

    input.value = polyStr(this.irr);
    const repr = this.m > 150 ? '' : `  |  Hex: ${toHex(this.irr)}`;
    preview.textContent = '';
    preview.appendChild(document.createTextNode(`Selected: ${status}  |  `));
    const polySpan = document.createElement('span');
    polySpan.className = 'poly-font';
    polySpan.textContent = polyStr(this.irr);
    preview.appendChild(polySpan);
    preview.appendChild(document.createTextNode(`${repr}  |  Degree: ${degree(this.irr)}`));
    error.textContent = '';
    this.renderModulusOptions();
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
      error.textContent = 'Click Use Custom to validate irreducibility.';
      error.style.color = 'var(--yellow)';
    }

    preview.textContent = `Binary: ${toBin(val)}  |  Hex: ${toHex(val)}  |  Degree: ${deg}`;
  },

  resetIrreducible() {
    this.buildModulusOptions();
    this.updateIrreducibleDisplay();
  },

  buildModulusOptions() {
    const options = [];

    if (IRREDUCIBLE_DEFAULTS[this.m]) {
      options.push(makeModulusOption(IRREDUCIBLE_DEFAULTS[this.m], '\u2605 standard'));
    }

    if (STANDARD_LARGE_POLYS[this.m]) {
      options.push(makeModulusOption(polyFromExponents(STANDARD_LARGE_POLYS[this.m]), '\u2605 standard'));
    }

    if (SMALL_EXTRA_CANDIDATES[this.m]) {
      const seen = new Set(options.map(option => option.poly.toString()));
      for (const entry of SMALL_EXTRA_CANDIDATES[this.m]) {
        const poly = BigInt(entry);
        if (!seen.has(poly.toString()) && isIrreducibleRabin(poly)) {
          options.push(makeModulusOption(poly, 'LRS irreducible'));
          seen.add(poly.toString());
        }
      }
    }

    const hasOption = options.length > 0;
    if (!hasOption) {
      const generated = searchSparseIrreducible(this.m);
      if (generated) options.push(generated);
    }

    if (options.length === 0) {
      const fallback = (1n << BigInt(this.m)) | 1n;
      options.push(makeModulusOption(fallback, 'unverified placeholder'));
      document.getElementById('irr-error').textContent =
        `No sparse irreducible polynomial was found quickly for m=${this.m}. Enter a custom modulus.`;
    }

    options[0].selected = true;
    this.modulusOptions = options;
    this.irr = options[0].poly;
  },

  renderModulusOptions() {
    const button = document.getElementById('modulus-dropdown-btn');
    const menu = document.getElementById('modulus-dropdown-menu');
    button.innerHTML = '';
    menu.innerHTML = '';

    this.modulusOptions.forEach((option, index) => {
      const item = document.createElement('button');
      item.type = 'button';
      item.className = 'modulus-dropdown-item';
      if (option.selected) item.classList.add('active');
      this.renderModulusOptionContent(item, option);
      item.addEventListener('click', () => {
        this.selectModulusByIndex(index);
        menu.classList.add('hidden');
      });
      menu.appendChild(item);

      if (option.selected) {
        this.renderModulusOptionContent(button, option);
      }
    });
  },

  renderModulusOptionContent(target, option) {
    target.innerHTML = '';
    const status = document.createElement('span');
    status.className = 'plain-font';
    status.textContent = `${option.status} | `;

    const poly = document.createElement('span');
    poly.className = 'poly-font';
    poly.textContent = polyStr(option.poly);

    target.append(status, poly);
    if (this.m <= 150) {
      const hex = document.createElement('span');
      hex.className = 'plain-font';
      hex.textContent = ` | Hex: ${toHex(option.poly)}`;
      target.appendChild(hex);
    }
  },

  selectModulus(poly) {
    this.irr = poly;
    for (const option of this.modulusOptions) option.selected = option.poly === poly;
    this.updateIrreducibleDisplay();
    this.hideResults();
    this.renderFieldStats();
    this.renderFieldTables();
  },

  selectModulusByIndex(index) {
    const option = this.modulusOptions[index];
    if (!option) return;
    this.selectModulus(option.poly);
  },

  selectedModulusStatus() {
    const selected = this.modulusOptions.find(option => option.selected);
    return selected ? selected.status : '';
  },

  useCustomModulus() {
    const input = document.getElementById('irr-input');
    const error = document.getElementById('irr-error');
    const poly = parsePoly(input.value);
    const validationError = validateModulusPolynomial(poly, this.m);

    if (validationError) {
      error.textContent = validationError;
      error.style.color = 'var(--red)';
      return;
    }

    const option = makeModulusOption(poly, 'custom verified');
    this.modulusOptions.push(option);
    this.selectModulus(poly);
    error.textContent = 'Custom modulus verified and selected.';
    error.style.color = 'var(--green)';
    this.renderFieldTables();
  },

  updatePlaceholders() {
    for (const name of this.variableNames) {
      const input = this.getVariableValueInput(name);
      const fmt = this.getVariableFormat(name);
      if (fmt === 'bin') {
        input.placeholder = `${name} value in binary`;
      } else if (fmt === 'hex') {
        input.placeholder = `${name} value in hex`;
      } else {
        input.placeholder = `${name} = x^${Math.max(this.m - 1, 1)} + x + 1`;
      }
    }
  },

  // Parse input based on selected format. Returns BigInt or null (empty) or -1n (error).
  parseInput(str, fmt = 'bin') {
    str = str.trim();
    if (str === '') return null;

    if (fmt === 'bin') {
      if (!/^[01]+$/.test(str)) return -1n;
      return BigInt('0b' + str);
    } else if (fmt === 'hex') {
      if (!/^[0-9a-fA-F]+$/.test(str)) return -1n;
      return BigInt('0x' + str);
    } else {
      const val = parsePoly(str);
      return val === null ? -1n : val;
    }
  },

  formatValue(val, fmt = this.resultFormat) {
    if (val === null || val === undefined || val < 0n) return '';
    if (fmt === 'bin') return toBin(val);
    if (fmt === 'hex') return toHex(val);
    return polyStr(val);
  },

  sanitizeVariableName(name) {
    return name.trim().toUpperCase().replace(/[^A-Z0-9_]/g, '');
  },

  nextVariableName() {
    while (this.nextVariableCode <= 'Z'.charCodeAt(0)) {
      const name = String.fromCharCode(this.nextVariableCode++);
      if (!this.variableNames.includes(name)) return name;
    }
    let i = 1;
    while (this.variableNames.includes(`V${i}`)) i++;
    return `V${i}`;
  },

  getVariableRow(name) {
    return document.querySelector(`.variable-row[data-name="${name}"]`);
  },

  getVariableValueInput(name) {
    const row = this.getVariableRow(name);
    return row ? row.querySelector('.variable-value') : null;
  },

  getVariableFormat(name) {
    const row = this.getVariableRow(name);
    return row ? row.dataset.format || 'bin' : 'bin';
  },

  addVariable(preferredName, preferredFormat = 'bin', preferredColor) {
    const list = document.getElementById('variables-list');
    const name = preferredName || this.nextVariableName();
    if (this.variableNames.includes(name)) return;

    this.variableNames.push(name);

    const row = document.createElement('div');
    row.className = 'variable-row';
    row.dataset.name = name;
    row.dataset.format = preferredFormat;
    row.dataset.color = String(this.assignColorIndex(preferredColor));
    row.draggable = true;

    const nameInput = document.createElement('input');
    nameInput.className = 'variable-name';
    nameInput.value = name;
    nameInput.title = 'Variable name';
    nameInput.autocomplete = 'off';
    nameInput.spellcheck = false;

    const valueInput = document.createElement('input');
    valueInput.className = 'variable-value';
    valueInput.autocomplete = 'off';
    valueInput.spellcheck = false;

    const formatToggle = document.createElement('div');
    formatToggle.className = 'mini-format-toggle variable-format-toggle';
    formatToggle.title = 'Variable input format';
    for (const [fmt, label] of [['bin', 'Bin.'], ['hex', 'Hex'], ['poly', 'Poly']]) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.dataset.format = fmt;
      btn.textContent = label;
      if (fmt === preferredFormat) btn.classList.add('active');
      btn.addEventListener('click', () => this.setVariableFormat(row.dataset.name, fmt));
      formatToggle.appendChild(btn);
    }

    const preview = document.createElement('div');
    preview.className = 'variable-preview';
    preview.textContent = 'Empty';

    const error = document.createElement('div');
    error.className = 'variable-error';

    const remove = document.createElement('button');
    remove.className = 'remove-variable-btn';
    remove.type = 'button';
    remove.title = 'Remove variable';
    remove.textContent = '\u00D7';

    nameInput.addEventListener('change', () => this.renameVariable(row, nameInput.value));
    valueInput.addEventListener('input', () => {
      this.updateVariablePreview(row.dataset.name);
      this.updateFormulaPreview();
    });
    this.bindPolynomialTyping(valueInput, () => row.dataset.format === 'poly');
    remove.addEventListener('click', () => this.removeVariable(row.dataset.name));

    this.attachDragHandlers(row);

    row.append(nameInput, formatToggle, valueInput, remove, preview, error);
    list.appendChild(row);

    this.updatePlaceholders();
    this.updateFormulaToolbar();
    this.updateVariablePreview(name);
    this.updateFormulaPreview();
  },

  setVariableFormat(name, fmt) {
    const row = this.getVariableRow(name);
    if (!row) return;

    const oldFmt = row.dataset.format || 'bin';
    const input = row.querySelector('.variable-value');
    const value = this.parseInput(input.value, oldFmt);

    row.dataset.format = fmt;
    row.querySelectorAll('.variable-format-toggle button').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.format === fmt);
    });

    if (value !== null && value !== -1n && input.value.trim() !== '') {
      input.value = this.formatValue(value, fmt);
    }

    this.updatePlaceholders();
    this.updateVariablePreview(name);
    this.updateFormulaPreview();
  },

  bindPolynomialTyping(input, isActive) {
    if (input.dataset.polyTypingBound === 'true') return;
    input.dataset.polyTypingBound = 'true';

    input.addEventListener('keydown', event => {
      if (!isActive()) return;

      if (event.key === '^') {
        event.preventDefault();
        input.dataset.exponentMode = 'true';
        return;
      }

      if (input.dataset.exponentMode === 'true') {
        if (/^\d$/.test(event.key)) {
          event.preventDefault();
          insertAtCursor(input, digitsToSuperscript(event.key));
          return;
        }
        input.dataset.exponentMode = 'false';
      }
    });

    input.addEventListener('input', () => {
      if (!isActive()) return;
      const normalized = normalizeSuperscriptNotation(input.value);
      if (normalized !== input.value) {
        const delta = input.value.length - normalized.length;
        const cursor = Math.max(0, input.selectionStart - delta);
        input.value = normalized;
        input.setSelectionRange(cursor, cursor);
        input.dispatchEvent(new Event('input', { bubbles: true }));
      }
    });
  },

  renameVariable(row, rawName) {
    const oldName = row.dataset.name;
    const nameInput = row.querySelector('.variable-name');
    const newName = this.sanitizeVariableName(rawName);

    if (!newName || ['XOR', 'INV'].includes(newName) || this.variableNames.includes(newName)) {
      nameInput.value = oldName;
      this.updateVariablePreview(oldName);
      return;
    }

    const idx = this.variableNames.indexOf(oldName);
    if (idx !== -1) this.variableNames[idx] = newName;
    row.dataset.name = newName;
    nameInput.value = newName;
    this.updatePlaceholders();
    this.updateFormulaToolbar();
    this.updateVariablePreview(newName);
    this.updateFormulaPreview();
  },

  removeVariable(name) {
    const row = this.getVariableRow(name);
    if (!row) return;
    row.remove();
    this.variableNames = this.variableNames.filter(v => v !== name);
    this.updateFormulaToolbar();
    this.updateFormulaPreview();
  },

  updateFormulaToolbar() {
    const toolbar = document.querySelector('.formula-toolbar');
    const fixedButtons = [
      [' + ', '+'],
      [' \u2295 ', '\u2295'],
      [' \u00D7 ', '\u00D7'],
      [' \u00F7 ', '\u00F7'],
      ['^', 'xⁿ'],
      ['inv(', 'inv'],
      ['(', '('],
      [')', ')']
    ];

    toolbar.innerHTML = '';
    for (const name of this.variableNames) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.dataset.token = name;
      btn.textContent = name;
      btn.addEventListener('click', () => this.insertFormulaToken(name));
      toolbar.appendChild(btn);
    }

    for (const [token, label] of fixedButtons) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.dataset.token = token;
      btn.textContent = label;
      btn.addEventListener('click', () => this.insertFormulaToken(token));
      toolbar.appendChild(btn);
    }
  },

  updateVariablePreview(name) {
    const row = this.getVariableRow(name);
    if (!row) return;
    const input = row.querySelector('.variable-value');
    const preview = row.querySelector('.variable-preview');
    const error = row.querySelector('.variable-error');
    const fmt = row.dataset.format || 'bin';
    const str = input.value.trim();

    error.textContent = '';
    error.style.color = '';

    if (str === '') {
      preview.textContent = 'Empty';
      preview.style.color = 'var(--text-muted)';
      this.updateDegreeBadge(row, null, 'empty');
      return;
    }

    const val = this.parseInput(str, fmt);
    if (val === -1n) {
      preview.textContent = '';
      if (fmt === 'bin') error.textContent = 'Invalid: use 0 and 1';
      else if (fmt === 'hex') error.textContent = 'Invalid: use 0-9 and A-F';
      else error.textContent = 'Invalid polynomial';
      this.updateDegreeBadge(row, null, 'invalid');
      return;
    }

    if (val === null) {
      preview.textContent = 'Empty';
      preview.style.color = 'var(--text-muted)';
      this.updateDegreeBadge(row, null, 'empty');
      return;
    }

    if (fmt === 'bin') {
      preview.textContent = '';
      const hexLine = document.createElement('div');
      hexLine.className = 'preview-alt-line';
      hexLine.textContent = compactPreview('Hex', toHex(val));
      const polyLine = document.createElement('div');
      polyLine.className = 'preview-poly-line';
      polyLine.appendChild(document.createTextNode('Poly: '));
      const polySpan = document.createElement('span');
      polySpan.className = 'poly-font';
      polySpan.textContent = polyStr(val);
      polyLine.appendChild(polySpan);
      preview.append(hexLine, polyLine);
    } else if (fmt === 'hex') {
      preview.textContent = '';
      const binLine = document.createElement('div');
      binLine.className = 'preview-alt-line';
      binLine.textContent = compactPreview('Bin', toBin(val));
      const polyLine = document.createElement('div');
      polyLine.className = 'preview-poly-line';
      polyLine.appendChild(document.createTextNode('Poly: '));
      const polySpan = document.createElement('span');
      polySpan.className = 'poly-font';
      polySpan.textContent = polyStr(val);
      polyLine.appendChild(polySpan);
      preview.append(binLine, polyLine);
    } else {
      preview.textContent = '';
      const binLine = document.createElement('div');
      binLine.className = 'preview-alt-line';
      binLine.textContent = compactPreview('Bin', toBin(val));
      const hexLine = document.createElement('div');
      hexLine.className = 'preview-alt-line';
      hexLine.textContent = compactPreview('Hex', toHex(val));
      preview.append(binLine, hexLine);
    }
    preview.style.color = 'var(--cyan)';

    if (degree(val) >= this.m) {
      error.textContent = `Degree ${degree(val)} \u2265 m=${this.m}; reduced before evaluation.`;
      error.style.color = 'var(--yellow)';
    }

    this.updateDegreeBadge(row, val);
  },

  getFormulaVariables() {
    const vars = {};

    for (const name of this.variableNames) {
      const input = this.getVariableValueInput(name);
      const fmt = this.getVariableFormat(name);
      if (!input) continue;
      const str = input.value.trim();
      if (str === '') continue;

      const value = this.parseInput(str, fmt);
      if (value === -1n || value === null) {
        throw new Error(`Variable ${name} is invalid.`);
      }
      vars[name] = {
        value: degree(value) >= this.m ? reduceSimple(value, this.irr) : value,
        originalValue: value
      };
    }

    return vars;
  },

  insertFormulaToken(token) {
    const input = document.getElementById('formula-input');
    const start = input.selectionStart;
    const end = input.selectionEnd;
    input.value = input.value.slice(0, start) + token + input.value.slice(end);
    const cursor = start + token.length;
    input.focus();
    input.setSelectionRange(cursor, cursor);
    this.recordFormulaHistory();
  },

  clearFormula() {
    document.getElementById('formula-input').value = '';
    this.recordFormulaHistory();
  },

  onFormulaInput() {
    if (this.recordingFormulaHistory) {
      this.recordFormulaHistory();
    } else {
      this.updateFormulaPreview();
    }
  },

  recordFormulaHistory() {
    const input = document.getElementById('formula-input');
    const value = input.value;
    if (this.formulaHistory[this.formulaHistoryIndex] === value) {
      this.updateFormulaPreview();
      return;
    }

    this.formulaHistory = this.formulaHistory.slice(0, this.formulaHistoryIndex + 1);
    this.formulaHistory.push(value);
    if (this.formulaHistory.length > 100) {
      this.formulaHistory.shift();
    } else {
      this.formulaHistoryIndex++;
    }
    this.updateFormulaPreview();
  },

  restoreFormulaHistory() {
    const input = document.getElementById('formula-input');
    this.recordingFormulaHistory = false;
    input.value = this.formulaHistory[this.formulaHistoryIndex] || '';
    this.recordingFormulaHistory = true;
    this.updateFormulaPreview();
    input.focus();
    input.setSelectionRange(input.value.length, input.value.length);
  },

  undoFormula() {
    if (this.formulaHistoryIndex === 0) return;
    this.formulaHistoryIndex--;
    this.restoreFormulaHistory();
  },

  redoFormula() {
    if (this.formulaHistoryIndex >= this.formulaHistory.length - 1) return;
    this.formulaHistoryIndex++;
    this.restoreFormulaHistory();
  },

  async pasteFormula() {
    const input = document.getElementById('formula-input');
    try {
      const text = await navigator.clipboard.readText();
      const start = input.selectionStart;
      const end = input.selectionEnd;
      input.value = input.value.slice(0, start) + text + input.value.slice(end);
      const cursor = start + text.length;
      input.focus();
      input.setSelectionRange(cursor, cursor);
      this.recordFormulaHistory();
    } catch (err) {
      this.showError('Clipboard paste is not available in this browser context.');
    }
  },

  setResultFormat(fmt) {
    this.resultFormat = fmt;
    document.querySelectorAll('#result-format-toggle button').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.format === fmt);
    });
    if (this.lastResult !== null) {
      this.showResult(this.lastResult, 'formula');
    }
  },

  updateFormulaPreview() {
    const input = document.getElementById('formula-input');
    const preview = document.getElementById('formula-preview');
    const error = document.getElementById('formula-error');
    const formula = input.value.trim();

    error.textContent = '';
    if (formula === '') {
      preview.textContent = 'Use your variables with +, xor, *, /, inv(...), and parentheses.';
      preview.style.color = 'var(--text-muted)';
      return;
    }

    try {
      const tokens = tokenizeFormula(formula);
      this.renderColoredFormulaPreview(preview, tokens);
      preview.style.color = '';
    } catch (err) {
      preview.textContent = '';
      error.textContent = err.message;
    }
  },

  hideResults() {
    document.getElementById('result-section').classList.add('hidden');
    document.getElementById('steps-section').classList.add('hidden');
    const viz = document.getElementById('bit-viz');
    if (viz) viz.classList.add('hidden');
    const btn = document.getElementById('toggle-bit-viz');
    if (btn) btn.classList.remove('active');
    this.showingBitViz = false;
  },

  computeFormula() {
    const formula = document.getElementById('formula-input').value.trim();
    if (formula === '') {
      this.showError('Enter a formula to evaluate.');
      return;
    }

    if (degree(this.irr) !== this.m) {
      this.showError(`Irreducible polynomial has degree ${degree(this.irr)}, expected ${this.m}. Fix it above.`);
      return;
    }
    if (this.selectedModulusStatus() === 'unverified placeholder') {
      this.showError('The selected modulus is not verified irreducible. Choose or enter a valid modulus first.');
      return;
    }

    try {
      const variables = this.getFormulaVariables();
      const tokens = tokenizeFormula(formula);
      const parser = new FormulaParser(tokens, variables, this);
      const output = parser.parse();
      this.lastResult = output.value;

      const steps = [
        { label: 'Formula', text: formula, section: true },
        ...this.variableNames
          .filter(name => variables[name])
          .map(name => ({
            label: `Variable ${name}`,
            text: variables[name].originalValue !== variables[name].value
              ? `${name} = ${polyStr(variables[name].originalValue)} reduced to ${polyStr(variables[name].value)}`
              : `${name} = ${polyStr(variables[name].value)}`
          })),
        ...parser.steps,
        { label: 'Final Result', text: `${toBin(output.value)}  =  ${polyStr(output.value)}`, highlight: true }
      ];

      this.showResult(output.value, 'formula');
      this.showSteps(steps);
      this.recordHistoryEntry(formula, output.value, variables);
    } catch (err) {
      this.showError(err.message);
      this.showSteps([{ label: 'Formula Error', text: err.message, error: true }]);
    }
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
      inv: 'Multiplicative Inverse',
      formula: 'Formula Result'
    };
    title.textContent = opNames[op] || 'Result';

    // Primary display based on selected result format (natural width)
    if (this.resultFormat === 'bin') {
      valEl.textContent = toBin(val);
    } else if (this.resultFormat === 'hex') {
      valEl.textContent = toHex(val);
    } else {
      valEl.textContent = polyStr(val);
    }
    valEl.classList.toggle('math-value', this.resultFormat === 'poly');
    this.lastDisplayedResult = valEl.textContent;

    // Polynomial notation (always shown)
    polyEl.textContent = this.resultFormat === 'poly' ? '' : polyStr(val);

    // Alternate representations
    const parts = [];
    if (this.resultFormat !== 'bin') parts.push(`Bin: ${toBin(val)}`);
    if (this.resultFormat !== 'hex') parts.push(`Hex: ${toHex(val)}`);
    if (this.resultFormat !== 'poly') parts.push(`Poly: ${polyStr(val)}`);
    altEl.textContent = parts.join('  |  ');

    this.renderBitVisualization(val);
    const sticky = document.getElementById('sticky-value');
    if (sticky) sticky.textContent = this.formatValue(val, this.resultFormat) || polyStr(val);
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
    this.lastDisplayedResult = '';

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

      const label = document.createElement('span');
      label.className = 'step-label';
      label.textContent = step.label;
      const text = document.createElement('span');
      text.className = 'step-text';
      renderStepText(text, step.text, step.label);
      div.append(label, text);
      container.appendChild(div);
    }

    section.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  },

  useResultAsVariable() {
    if (this.lastResult === null) return;
    const name = this.nextVariableName();
    this.addVariable(name, this.resultFormat);
    const input = this.getVariableValueInput(name);
    input.value = this.formatValue(this.lastResult, this.resultFormat);
    this.updateVariablePreview(name);
    this.updateFormulaPreview();
  },

  async copyResult() {
    if (!this.lastDisplayedResult) return;
    try {
      await navigator.clipboard.writeText(this.lastDisplayedResult);
    } catch (err) {
      this.showError('Clipboard copy is not available in this browser context.');
    }
  },

  // ===================== COLLAPSIBLE SECTIONS =====================

  bindCollapsibles() {
    document.querySelectorAll('.collapse-toggle').forEach(btn => {
      btn.addEventListener('click', () => {
        const section = btn.closest('.collapsible-section');
        if (section) section.classList.toggle('collapsed');
      });
    });
  },

  // ===================== KEYBOARD SHORTCUTS =====================

  bindKeyboardShortcuts() {
    document.addEventListener('keydown', event => {
      const ctrl = event.ctrlKey || event.metaKey;
      const formulaInput = document.getElementById('formula-input');
      const inEditable = ['INPUT', 'TEXTAREA'].includes(document.activeElement && document.activeElement.tagName);

      if (ctrl && (event.key === 'k' || event.key === 'K')) {
        event.preventDefault();
        this.openCommandPalette();
        return;
      }

      if (ctrl && event.key === 'Enter') {
        event.preventDefault();
        this.computeFormula();
        return;
      }

      if (ctrl && event.key.toLowerCase() === 'l' && document.activeElement === formulaInput) {
        event.preventDefault();
        this.clearFormula();
        formulaInput.focus();
        return;
      }

      if (event.key === 'Escape' && !inEditable) {
        this.hideResults();
        return;
      }

      if (event.key === 'Escape' && document.activeElement === formulaInput) {
        formulaInput.blur();
        this.hideResults();
      }
    });
  },

  // ===================== BIT VISUALIZATION =====================

  toggleBitViz() {
    this.showingBitViz = !this.showingBitViz;
    const btn = document.getElementById('toggle-bit-viz');
    btn.classList.toggle('active', this.showingBitViz);
    if (this.lastResult !== null) {
      this.renderBitVisualization(this.lastResult);
    }
  },

  renderBitVisualization(val) {
    const container = document.getElementById('bit-viz');
    if (!container) return;

    if (!this.showingBitViz || val === null || val === undefined) {
      container.classList.add('hidden');
      container.innerHTML = '';
      return;
    }

    container.classList.remove('hidden');
    container.innerHTML = '';

    const bits = this.m;
    if (bits > 64) {
      const note = document.createElement('div');
      note.className = 'bit-viz-note';
      note.textContent = `Bit visualization is hidden for m=${bits} (too large to render). Switch to a smaller field.`;
      container.appendChild(note);
      return;
    }

    for (let i = bits - 1; i >= 0; i--) {
      const bit = (val >> BigInt(i)) & 1n;
      const cell = document.createElement('div');
      cell.className = 'bit-cell' + (bit === 1n ? ' set' : '');
      cell.title = i === 0 ? 'constant term (1)' : i === 1 ? 'x' : `x^${i}`;
      const valueEl = document.createElement('span');
      valueEl.className = 'bit-value';
      valueEl.textContent = String(bit);
      const expEl = document.createElement('span');
      expEl.className = 'bit-exp';
      expEl.textContent = i.toString();
      cell.append(valueEl, expEl);
      container.appendChild(cell);
    }
  },

  // ===================== HISTORY =====================

  loadHistory() {
    try {
      const stored = localStorage.getItem(HISTORY_STORAGE_KEY);
      this.history = stored ? JSON.parse(stored) : [];
      if (!Array.isArray(this.history)) this.history = [];
    } catch (e) {
      this.history = [];
    }
  },

  saveHistory() {
    try {
      localStorage.setItem(
        HISTORY_STORAGE_KEY,
        JSON.stringify(this.history.slice(0, HISTORY_MAX_ENTRIES))
      );
    } catch (e) {
      // localStorage might be full or unavailable; ignore silently
    }
  },

  recordHistoryEntry(formula, result, variables) {
    const entry = {
      timestamp: Date.now(),
      m: this.m,
      irrHex: this.irr.toString(16),
      irrPoly: polyStr(this.irr),
      formula,
      formulaDisplay: formatFormulaDisplay(formula),
      resultBin: toBin(result),
      resultHex: toHex(result),
      resultPoly: polyStr(result),
      resultFormat: this.resultFormat,
      variables: this.variableNames
        .filter(name => variables[name])
        .map(name => {
          const row = this.getVariableRow(name);
          const input = this.getVariableValueInput(name);
          return {
            name,
            format: (row && row.dataset.format) || 'bin',
            value: (input && input.value) || ''
          };
        })
    };

    this.history.unshift(entry);
    if (this.history.length > HISTORY_MAX_ENTRIES) {
      this.history.length = HISTORY_MAX_ENTRIES;
    }
    this.saveHistory();
    this.renderHistory();
  },

  renderHistory() {
    const list = document.getElementById('history-list');
    if (!list) return;

    list.innerHTML = '';

    if (this.history.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'history-empty';
      empty.textContent = 'No saved calculations yet. Evaluate a formula to start your history.';
      list.appendChild(empty);
      return;
    }

    this.history.forEach((entry, idx) => {
      const item = document.createElement('div');
      item.className = 'history-item';

      const main = document.createElement('div');
      main.className = 'history-main';

      const formula = document.createElement('div');
      formula.className = 'history-formula';
      formula.textContent = entry.formulaDisplay || formatFormulaDisplay(entry.formula);

      const result = document.createElement('div');
      result.className = 'history-result';
      result.textContent = `= ${entry.resultPoly}`;

      const meta = document.createElement('div');
      meta.className = 'history-meta';
      const mBadge = document.createElement('span');
      mBadge.className = 'badge';
      mBadge.textContent = `m=${entry.m}`;
      const irrBadge = document.createElement('span');
      irrBadge.className = 'badge';
      irrBadge.textContent = `mod ${entry.irrPoly}`;
      const date = new Date(entry.timestamp);
      const dateText = document.createElement('span');
      dateText.textContent = date.toLocaleString();
      meta.append(mBadge, irrBadge, dateText);

      main.append(formula, result, meta);

      const actions = document.createElement('div');
      actions.className = 'history-actions';

      const reimport = document.createElement('button');
      reimport.className = 'small-btn';
      reimport.type = 'button';
      reimport.textContent = 'Re-import';
      reimport.title = 'Restore field, variables, and formula from this entry';
      reimport.addEventListener('click', () => this.reimportHistory(idx));

      const remove = document.createElement('button');
      remove.className = 'small-btn history-remove';
      remove.type = 'button';
      remove.textContent = '×';
      remove.title = 'Delete this entry';
      remove.addEventListener('click', () => this.removeHistoryEntry(idx));

      actions.append(reimport, remove);
      item.append(main, actions);
      list.appendChild(item);
    });
  },

  reimportHistory(idx) {
    const entry = this.history[idx];
    if (!entry) return;

    this.applyState({
      m: entry.m,
      irrHex: entry.irrHex,
      formula: entry.formula,
      resultFormat: entry.resultFormat,
      variables: entry.variables
    });
  },

  removeHistoryEntry(idx) {
    this.history.splice(idx, 1);
    this.saveHistory();
    this.renderHistory();
  },

  clearHistory() {
    if (this.history.length === 0) return;
    if (!confirm('Clear all calculation history? This cannot be undone.')) return;
    this.history = [];
    this.saveHistory();
    this.renderHistory();
  },

  // ===================== WORKSPACE EXPORT/IMPORT =====================

  exportWorkspace() {
    const data = {
      kind: 'gf2m-workspace',
      version: 1,
      timestamp: Date.now(),
      m: this.m,
      irrHex: this.irr.toString(16),
      irrPoly: polyStr(this.irr),
      resultFormat: this.resultFormat,
      formula: document.getElementById('formula-input').value,
      variables: this.variableNames.map(name => {
        const row = this.getVariableRow(name);
        const input = this.getVariableValueInput(name);
        return {
          name,
          format: (row && row.dataset.format) || 'bin',
          value: (input && input.value) || ''
        };
      }),
      history: this.history
    };

    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const stamp = new Date().toISOString().slice(0, 10);
    a.download = `gf2m-workspace-${stamp}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  },

  async importWorkspaceFile(file) {
    try {
      const text = await file.text();
      const data = JSON.parse(text);
      if (!data || typeof data !== 'object') throw new Error('Invalid workspace file (not an object).');

      this.applyState({
        m: data.m,
        irrHex: data.irrHex,
        formula: data.formula,
        resultFormat: data.resultFormat,
        variables: Array.isArray(data.variables) ? data.variables : []
      });

      if (Array.isArray(data.history)) {
        this.history = data.history.slice(0, HISTORY_MAX_ENTRIES);
        this.saveHistory();
        this.renderHistory();
      }
    } catch (err) {
      this.showError(`Could not import workspace: ${err.message}`);
    }
  },

  applyState(state) {
    if (typeof state.m === 'number' && state.m >= 2 && state.m <= 571) {
      if (state.m !== this.m) this.setDegree(state.m);
    }

    if (typeof state.irrHex === 'string' && state.irrHex.length > 0) {
      try {
        const irr = BigInt('0x' + state.irrHex);
        if (degree(irr) === this.m) {
          if (!this.modulusOptions.find(o => o.poly === irr)) {
            this.modulusOptions.push(makeModulusOption(irr, 'imported'));
          }
          this.selectModulus(irr);
        }
      } catch (e) {
        // ignore bad hex
      }
    }

    // Reset variables to imported set
    for (const name of [...this.variableNames]) this.removeVariable(name);
    this.nextVariableCode = 'A'.charCodeAt(0);
    if (Array.isArray(state.variables)) {
      for (const v of state.variables) {
        if (!v || typeof v.name !== 'string') continue;
        const safeName = this.sanitizeVariableName(v.name);
        if (!safeName || ['XOR', 'INV'].includes(safeName)) continue;
        this.addVariable(safeName, v.format === 'hex' || v.format === 'poly' ? v.format : 'bin');
        const input = this.getVariableValueInput(safeName);
        if (input) input.value = typeof v.value === 'string' ? v.value : '';
        this.updateVariablePreview(safeName);
      }
    }

    if (typeof state.formula === 'string') {
      const formulaInput = document.getElementById('formula-input');
      formulaInput.value = state.formula;
      this.recordFormulaHistory();
    }

    if (state.resultFormat === 'bin' || state.resultFormat === 'hex' || state.resultFormat === 'poly') {
      this.setResultFormat(state.resultFormat);
    }

    this.updateFormulaPreview();
    this.hideResults();
  }
  ,

  // ===================== VARIABLE COLOR + DEGREE BADGE =====================

  assignColorIndex(preferred) {
    const palette = 6;
    const used = new Set(this.variableNames
      .map(n => this.getVariableRow(n))
      .filter(r => r)
      .map(r => r.dataset.color));
    if (preferred !== undefined && preferred !== null) {
      const i = ((Number(preferred) % palette) + palette) % palette;
      return i;
    }
    for (let i = 0; i < palette; i++) {
      if (!used.has(String(i))) return i;
    }
    return this.variableNames.length % palette;
  },

  updateDegreeBadge(row, val, state) {
    if (!row) return;
    let badge = row.querySelector('.variable-degree-badge');
    if (!badge) {
      badge = document.createElement('span');
      badge.className = 'variable-degree-badge';
      const dot = document.createElement('span');
      dot.className = 'badge-dot';
      const text = document.createElement('span');
      text.className = 'badge-text';
      badge.append(dot, text);
      const preview = row.querySelector('.variable-preview');
      if (preview) preview.appendChild(badge);
    }
    const text = badge.querySelector('.badge-text');
    badge.classList.remove('in-field', 'over-field', 'invalid');
    if (state === 'empty') {
      text.textContent = 'empty';
      return;
    }
    if (state === 'invalid' || val === null || val === undefined) {
      text.textContent = 'invalid';
      badge.classList.add('invalid');
      return;
    }
    const d = degree(val);
    if (val === 0n) {
      text.textContent = `0 in F`;
      badge.classList.add('in-field');
      return;
    }
    if (d < this.m) {
      text.textContent = `deg ${d} < m=${this.m}`;
      badge.classList.add('in-field');
    } else {
      text.textContent = `deg ${d} ≥ m=${this.m} (will reduce)`;
      badge.classList.add('over-field');
    }
  },

  // ===================== COLORED FORMULA PREVIEW =====================

  renderColoredFormulaPreview(container, tokens) {
    container.textContent = '';
    container.appendChild(document.createTextNode('Formula: '));
    for (const t of tokens) {
      if (t.type === 'var') {
        const span = document.createElement('span');
        span.className = 'var-token';
        const row = this.getVariableRow(t.value);
        if (row) span.dataset.color = row.dataset.color;
        span.textContent = t.value;
        container.appendChild(span);
      } else if (t.type === '(' || t.type === ')') {
        const span = document.createElement('span');
        span.className = 'formula-paren';
        span.textContent = t.value;
        container.appendChild(span);
      } else if (t.type === '+' || t.type === '-' || t.type === '*' || t.type === '/' || t.type === 'xor' || t.type === '^') {
        const span = document.createElement('span');
        span.className = 'formula-op-token';
        const sym = t.type === '*' ? ' × ' : t.type === '/' ? ' ÷ ' : t.type === 'xor' ? ' ⊕ ' : t.type === '^' ? '^' : ` ${t.value} `;
        span.textContent = sym;
        container.appendChild(span);
      } else if (t.type === 'inv') {
        const span = document.createElement('span');
        span.className = 'formula-op-token';
        span.textContent = 'inv';
        container.appendChild(span);
      } else if (t.type === 'intnum' || t.type === 'number' || t.type === 'literal') {
        container.appendChild(document.createTextNode(t.value));
      }
    }
  },

  // ===================== DRAG-AND-DROP REORDER =====================

  attachDragHandlers(row) {
    row.addEventListener('dragstart', (event) => {
      this._draggingRow = row;
      row.classList.add('dragging');
      try {
        event.dataTransfer.effectAllowed = 'move';
        event.dataTransfer.setData('text/plain', row.dataset.name || '');
      } catch (e) { /* ignore */ }
    });
    row.addEventListener('dragend', () => {
      row.classList.remove('dragging');
      document.querySelectorAll('.variable-row').forEach(r => {
        r.classList.remove('drop-target-above', 'drop-target-below');
      });
      this._draggingRow = null;
    });
    row.addEventListener('dragover', (event) => {
      if (!this._draggingRow || this._draggingRow === row) return;
      event.preventDefault();
      const rect = row.getBoundingClientRect();
      const above = (event.clientY - rect.top) < rect.height / 2;
      row.classList.toggle('drop-target-above', above);
      row.classList.toggle('drop-target-below', !above);
    });
    row.addEventListener('dragleave', () => {
      row.classList.remove('drop-target-above', 'drop-target-below');
    });
    row.addEventListener('drop', (event) => {
      event.preventDefault();
      if (!this._draggingRow || this._draggingRow === row) return;
      const rect = row.getBoundingClientRect();
      const above = (event.clientY - rect.top) < rect.height / 2;
      const list = document.getElementById('variables-list');
      list.insertBefore(this._draggingRow, above ? row : row.nextSibling);
      // Re-sync this.variableNames from DOM order
      this.variableNames = Array.from(list.querySelectorAll('.variable-row'))
        .map(r => r.dataset.name);
      row.classList.remove('drop-target-above', 'drop-target-below');
      this.updateFormulaToolbar();
      this.updateFormulaPreview();
    });
  },

  // ===================== QUICK CONVERTER =====================

  bindConverter() {
    const bin = document.getElementById('conv-bin');
    const hex = document.getElementById('conv-hex');
    const poly = document.getElementById('conv-poly');
    const dec = document.getElementById('conv-dec');
    const info = document.getElementById('conv-info');
    if (!bin || !hex || !poly || !dec) return;
    if (poly) poly.classList.add('poly-input');
    this.bindPolynomialTyping(poly, () => true);

    const setError = (msg) => {
      info.classList.add('error');
      info.textContent = msg;
    };
    const setOK = (val) => {
      info.classList.remove('error');
      const d = degree(val);
      info.textContent = val === 0n
        ? '0 (zero polynomial)'
        : `degree ${d}, ${d + 1} bit${d === 0 ? '' : 's'}`;
    };

    const updateAll = (source, val) => {
      if (val === null) {
        bin.value = ''; hex.value = ''; poly.value = ''; dec.value = '';
        info.textContent = '';
        info.classList.remove('error');
        return;
      }
      if (source !== 'bin') bin.value = toBin(val);
      if (source !== 'hex') hex.value = toHex(val);
      if (source !== 'poly') poly.value = polyStr(val);
      if (source !== 'dec') dec.value = val.toString(10);
      setOK(val);
    };

    bin.addEventListener('input', () => {
      const s = bin.value.trim();
      if (s === '') return updateAll('bin', null);
      if (!/^[01]+$/.test(s)) return setError('Binary: use only 0 and 1.');
      try { updateAll('bin', BigInt('0b' + s)); } catch (e) { setError('Invalid binary.'); }
    });
    hex.addEventListener('input', () => {
      const s = hex.value.trim();
      if (s === '') return updateAll('hex', null);
      if (!/^[0-9a-fA-F]+$/.test(s)) return setError('Hex: use only 0-9 and A-F.');
      try { updateAll('hex', BigInt('0x' + s)); } catch (e) { setError('Invalid hex.'); }
    });
    poly.addEventListener('input', () => {
      const s = poly.value.trim();
      if (s === '') return updateAll('poly', null);
      const v = parsePoly(s);
      if (v === null) return setError('Polynomial: use x^n + ... format.');
      updateAll('poly', v);
    });
    dec.addEventListener('input', () => {
      const s = dec.value.trim();
      if (s === '') return updateAll('dec', null);
      if (!/^\d+$/.test(s)) return setError('Decimal: use only digits.');
      try { updateAll('dec', BigInt(s)); } catch (e) { setError('Invalid decimal.'); }
    });
  },

  // ===================== PINNED RESULTS =====================

  loadPinned() {
    try {
      const stored = localStorage.getItem('gf2m-calc-pinned-v1');
      this.pinned = stored ? JSON.parse(stored) : [];
      if (!Array.isArray(this.pinned)) this.pinned = [];
    } catch (e) {
      this.pinned = [];
    }
  },

  savePinned() {
    try {
      localStorage.setItem('gf2m-calc-pinned-v1', JSON.stringify(this.pinned.slice(0, 12)));
    } catch (e) { /* ignore */ }
  },

  pinCurrentResult() {
    if (this.lastResult === null) return;
    const formula = document.getElementById('formula-input').value.trim() || 'result';
    const entry = {
      timestamp: Date.now(),
      m: this.m,
      irrHex: this.irr.toString(16),
      irrPoly: polyStr(this.irr),
      formula,
      formulaDisplay: formatFormulaDisplay(formula),
      resultBin: toBin(this.lastResult),
      resultHex: toHex(this.lastResult),
      resultPoly: polyStr(this.lastResult),
      resultFormat: this.resultFormat
    };
    this.pinned.unshift(entry);
    if (this.pinned.length > 12) this.pinned.length = 12;
    this.savePinned();
    this.renderPinned();
  },

  removePinned(idx) {
    this.pinned.splice(idx, 1);
    this.savePinned();
    this.renderPinned();
  },

  clearPinned() {
    if (this.pinned.length === 0) return;
    if (!confirm('Remove all pinned results?')) return;
    this.pinned = [];
    this.savePinned();
    this.renderPinned();
  },

  renderPinned() {
    const list = document.getElementById('pinned-list');
    if (!list) return;
    list.innerHTML = '';
    if (this.pinned.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'pinned-empty';
      empty.textContent = 'No pinned results yet. Pin a result to compare it side-by-side later.';
      list.appendChild(empty);
      return;
    }
    this.pinned.forEach((entry, idx) => {
      const card = document.createElement('div');
      card.className = 'pinned-card';

      const formula = document.createElement('div');
      formula.className = 'pin-formula';
      formula.textContent = entry.formulaDisplay || formatFormulaDisplay(entry.formula);

      const result = document.createElement('div');
      result.className = 'pin-result';
      result.textContent = `= ${entry.resultPoly}`;

      const meta = document.createElement('div');
      meta.className = 'pin-meta';
      meta.textContent = `m=${entry.m}  •  hex ${entry.resultHex}`;

      const remove = document.createElement('button');
      remove.className = 'pin-remove';
      remove.type = 'button';
      remove.title = 'Unpin';
      remove.textContent = '×';
      remove.addEventListener('click', () => this.removePinned(idx));

      const actions = document.createElement('div');
      actions.className = 'pin-actions';
      const reimport = document.createElement('button');
      reimport.className = 'small-btn';
      reimport.type = 'button';
      reimport.textContent = 'Re-import';
      reimport.addEventListener('click', () => {
        this.applyState({
          m: entry.m,
          irrHex: entry.irrHex,
          formula: entry.formula,
          resultFormat: entry.resultFormat,
          variables: this.variableNames.map(n => ({
            name: n,
            format: this.getVariableFormat(n),
            value: (this.getVariableValueInput(n) || { value: '' }).value
          }))
        });
      });
      actions.appendChild(reimport);

      card.append(formula, result, meta, actions, remove);
      list.appendChild(card);
    });
  },

  // ===================== FIELD STATS PANEL =====================

  renderFieldStats() {
    const container = document.getElementById('field-stats');
    if (!container) return;
    container.innerHTML = '';

    const grid = document.createElement('div');
    grid.className = 'field-stats-grid';

    const addStat = (label, value, opts) => {
      const cell = document.createElement('div');
      cell.className = 'field-stat' + (opts && opts.cls ? ` ${opts.cls}` : '');
      const lbl = document.createElement('div');
      lbl.className = 'field-stat-label';
      lbl.textContent = label;
      const val = document.createElement('div');
      val.className = 'field-stat-value' + (opts && opts.poly ? ' poly-value' : '') + (opts && opts.muted ? ' muted' : '');
      val.textContent = value;
      cell.append(lbl, val);
      grid.appendChild(cell);
    };

    addStat('Field degree', `m = ${this.m}`);
    if (this.m <= 200) {
      const order = (1n << BigInt(this.m));
      addStat('|F|', `2^${this.m} = ${this.m <= 16 ? order.toString() : '2^' + this.m}`);
      const groupOrder = order - 1n;
      addStat('|F*|', `2^${this.m} − 1 = ${this.m <= 16 ? groupOrder.toString() : '2^' + this.m + '−1'}`);
    } else {
      addStat('|F|', `2^${this.m}`);
      addStat('|F*|', `2^${this.m} − 1`);
    }
    addStat('Modulus', polyStr(this.irr), { poly: true });
    addStat('Modulus hex', '0x' + this.irr.toString(16).toUpperCase());

    if (this.m <= 22) {
      const groupOrder = (1n << BigInt(this.m)) - 1n;
      const factors = primeFactorsBigInt(groupOrder);
      const factorString = factors.length
        ? factors.map(([p, e]) => e === 1 ? p.toString() : `${p}^${e}`).join(' · ')
        : '1';
      addStat('|F*| factors', factorString, { muted: true });

      // Primitive test: order of x in GF(2^m)
      const ord = orderOfX(this.m, this.irr, factors);
      const isPrim = ord === groupOrder;
      addStat('Modulus is primitive?', isPrim ? 'yes ✓' : 'no', { cls: isPrim ? 'primitive' : 'composite' });
      if (!isPrim && ord !== null) addStat('Order of x', ord.toString(), { muted: true });
    } else {
      addStat('Primitive?', 'unknown (m too large)', { muted: true });
    }

    container.appendChild(grid);

    // Generator orbit panel for small m
    if (this.m <= 8) {
      const orbit = document.createElement('div');
      orbit.className = 'orbit-panel';
      orbit.innerHTML = `
        <div class="orbit-controls">
          <label>Generator g (poly)</label>
          <input type="text" id="orbit-g" value="x" autocomplete="off" spellcheck="false">
          <span class="orbit-info" id="orbit-info"></span>
        </div>
        <div class="orbit-svg-wrap">
          <svg class="orbit-svg" id="orbit-svg" viewBox="0 0 360 360" xmlns="http://www.w3.org/2000/svg"></svg>
        </div>
        <div class="orbit-note">Click a point to see g<sup>k</sup>. Green dot is the identity (1).</div>
      `;
      container.appendChild(orbit);
      const input = orbit.querySelector('#orbit-g');
      this.bindPolynomialTyping(input, () => true);
      const refresh = () => this.renderGeneratorOrbit(input.value);
      input.addEventListener('input', refresh);
      refresh();
    } else if (this.m <= 16) {
      const note = document.createElement('div');
      note.className = 'orbit-note';
      note.textContent = `Orbit visualizer is shown for m ≤ 8 only (m=${this.m} would have ${(1n << BigInt(this.m)) - 1n} points).`;
      container.appendChild(note);
    }
  },

  renderGeneratorOrbit(gPolyStr) {
    const svg = document.getElementById('orbit-svg');
    const info = document.getElementById('orbit-info');
    if (!svg) return;
    svg.innerHTML = '';

    let g = parsePoly(gPolyStr);
    if (g === null || g === 0n) {
      info.textContent = 'invalid generator';
      return;
    }
    g = reduceSimple(g, this.irr);
    if (g === 0n) {
      info.textContent = 'g = 0 has no orbit';
      return;
    }

    const points = [1n];
    let p = g;
    const limit = (1n << BigInt(this.m)) - 1n;
    let safety = Number(limit) + 1;
    while (p !== 1n && safety-- > 0) {
      points.push(p);
      p = reduceSimple(mulRaw(p, g), this.irr);
    }
    if (p !== 1n) {
      info.textContent = 'orbit too long';
      return;
    }

    const order = points.length;
    info.textContent = `order ${order}` + (BigInt(order) === limit ? ' (primitive)' : '');

    const cx = 180, cy = 180, r = 140;
    // Background ring
    const bg = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    bg.setAttribute('cx', cx); bg.setAttribute('cy', cy); bg.setAttribute('r', r);
    bg.setAttribute('class', 'orbit-bg');
    svg.appendChild(bg);

    // Polyline
    const polyline = document.createElementNS('http://www.w3.org/2000/svg', 'polyline');
    polyline.setAttribute('class', 'orbit-line');
    let lineStr = '';
    const pos = [];
    for (let i = 0; i < order; i++) {
      const angle = (i / order) * 2 * Math.PI - Math.PI / 2;
      const x = cx + r * Math.cos(angle);
      const y = cy + r * Math.sin(angle);
      pos.push([x, y]);
      lineStr += `${x},${y} `;
    }
    if (order > 1) lineStr += `${pos[0][0]},${pos[0][1]}`;
    polyline.setAttribute('points', lineStr);
    svg.appendChild(polyline);

    // Center label
    const center = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    center.setAttribute('x', cx);
    center.setAttribute('y', cy + 5);
    center.setAttribute('class', 'orbit-center-label');
    center.textContent = `g = ${polyStr(g)}, ord = ${order}`;
    svg.appendChild(center);

    // Points + labels
    for (let i = 0; i < order; i++) {
      const [x, y] = pos[i];
      const c = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      c.setAttribute('cx', x);
      c.setAttribute('cy', y);
      c.setAttribute('r', 4.5);
      c.setAttribute('class', 'orbit-point' + (i === 0 ? ' identity' : ''));
      const tooltip = i === 0 ? '1 (identity)' : `g^${i} = ${polyStr(points[i])}`;
      const title = document.createElementNS('http://www.w3.org/2000/svg', 'title');
      title.textContent = tooltip;
      c.appendChild(title);
      svg.appendChild(c);

      if (order <= 32 || i % Math.ceil(order / 32) === 0) {
        const lx = cx + (r + 14) * Math.cos((i / order) * 2 * Math.PI - Math.PI / 2);
        const ly = cy + (r + 14) * Math.sin((i / order) * 2 * Math.PI - Math.PI / 2);
        const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        label.setAttribute('x', lx);
        label.setAttribute('y', ly + 3);
        label.setAttribute('text-anchor', 'middle');
        label.setAttribute('class', 'orbit-label');
        label.textContent = i === 0 ? '1' : `g${i}`;
        svg.appendChild(label);
      }
    }
  },

  // ===================== COMMAND PALETTE =====================

  openCommandPalette() {
    const overlay = document.getElementById('palette-overlay');
    const input = document.getElementById('palette-input');
    overlay.classList.remove('hidden');
    overlay.setAttribute('aria-hidden', 'false');
    input.value = '';
    this.paletteSelectedIndex = 0;
    this.renderPaletteResults('');
    setTimeout(() => input.focus(), 30);
  },

  closeCommandPalette() {
    const overlay = document.getElementById('palette-overlay');
    overlay.classList.add('hidden');
    overlay.setAttribute('aria-hidden', 'true');
  },

  paletteCommands() {
    return [
      { id: 'evaluate',   icon: '▶',  title: 'Evaluate formula',         desc: 'Run current formula', run: () => this.computeFormula() },
      { id: 'clear',      icon: '⌫', title: 'Clear formula',            desc: 'Empty the formula box', run: () => this.clearFormula() },
      { id: 'add-var',    icon: '+',  title: 'Add variable',             desc: 'Append a new variable row', run: () => this.addVariable() },
      { id: 'pin',        icon: '★',  title: 'Pin current result',      desc: 'Save result for comparison', run: () => this.pinCurrentResult() },
      { id: 'theme',      icon: '☾',  title: 'Toggle light / dark theme', desc: 'Switch theme', run: () => this.setTheme(document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light') },
      { id: 'fmt-bin',    icon: '01', title: 'Result format: binary',    desc: 'Show result in binary', run: () => this.setResultFormat('bin') },
      { id: 'fmt-hex',    icon: '0x', title: 'Result format: hex',       desc: 'Show result in hexadecimal', run: () => this.setResultFormat('hex') },
      { id: 'fmt-poly',   icon: 'xⁿ', title: 'Result format: polynomial', desc: 'Show result in polynomial notation', run: () => this.setResultFormat('poly') },
      { id: 'bits',       icon: '▦',  title: 'Toggle bit visualization', desc: 'Show/hide bit grid in result', run: () => this.toggleBitViz() },
      { id: 'export',     icon: '↓',  title: 'Export workspace JSON',    desc: 'Download current state', run: () => this.exportWorkspace() },
      { id: 'import',     icon: '↑',  title: 'Import workspace JSON',    desc: 'Load a workspace file', run: () => document.getElementById('workspace-file-input').click() },
      { id: 'export-fmt', icon: '∑',  title: 'Export current calculation as LaTeX / Markdown', desc: 'Generate report-ready math', run: () => this.openExportModal() },
      { id: 'undo',       icon: '↶',  title: 'Undo formula edit',        desc: 'Step formula history back', run: () => this.undoFormula() },
      { id: 'redo',       icon: '↷',  title: 'Redo formula edit',        desc: 'Step formula history forward', run: () => this.redoFormula() },
      { id: 'play',       icon: '▶',  title: 'Play step-by-step animation', desc: 'Animate the breakdown', run: () => this.startPlayback() },
      { id: 'history-clear', icon: '✕', title: 'Clear calculation history', desc: 'Wipe history list', run: () => this.clearHistory() },
      { id: 'pinned-clear',  icon: '✕', title: 'Clear pinned results', desc: 'Wipe pinned list', run: () => this.clearPinned() },
    ];
  },

  renderPaletteResults(query) {
    const list = document.getElementById('palette-results');
    list.innerHTML = '';
    const q = query.trim().toLowerCase();
    const all = this.paletteCommands();
    const filtered = q === ''
      ? all
      : all.filter(c =>
          c.title.toLowerCase().includes(q) ||
          (c.desc || '').toLowerCase().includes(q) ||
          c.id.includes(q)
        );

    if (filtered.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'palette-empty';
      empty.textContent = 'No matching commands';
      list.appendChild(empty);
      this.paletteFiltered = [];
      return;
    }

    this.paletteFiltered = filtered;
    if (this.paletteSelectedIndex >= filtered.length) this.paletteSelectedIndex = 0;
    filtered.forEach((c, idx) => {
      const item = document.createElement('div');
      item.className = 'palette-item' + (idx === this.paletteSelectedIndex ? ' active' : '');
      item.dataset.idx = idx;
      const icon = document.createElement('span');
      icon.className = 'palette-icon';
      icon.textContent = c.icon || '';
      const title = document.createElement('span');
      title.className = 'palette-item-title';
      title.textContent = c.title;
      const desc = document.createElement('span');
      desc.className = 'palette-item-desc';
      desc.textContent = c.desc || '';
      item.append(icon, title, desc);
      item.addEventListener('mouseenter', () => {
        this.paletteSelectedIndex = idx;
        list.querySelectorAll('.palette-item').forEach((el, i) => el.classList.toggle('active', i === idx));
      });
      item.addEventListener('click', () => this.runPaletteCommand(c));
      list.appendChild(item);
    });
  },

  runPaletteCommand(cmd) {
    this.closeCommandPalette();
    setTimeout(() => { try { cmd.run(); } catch (e) { /* ignore */ } }, 80);
  },

  bindCommandPalette() {
    const input = document.getElementById('palette-input');
    const overlay = document.getElementById('palette-overlay');
    if (!input || !overlay) return;

    input.addEventListener('input', () => {
      this.paletteSelectedIndex = 0;
      this.renderPaletteResults(input.value);
    });
    input.addEventListener('keydown', (event) => {
      const list = this.paletteFiltered || [];
      if (event.key === 'Escape') {
        event.preventDefault();
        this.closeCommandPalette();
      } else if (event.key === 'ArrowDown') {
        event.preventDefault();
        this.paletteSelectedIndex = Math.min(list.length - 1, this.paletteSelectedIndex + 1);
        this.renderPaletteResults(input.value);
      } else if (event.key === 'ArrowUp') {
        event.preventDefault();
        this.paletteSelectedIndex = Math.max(0, this.paletteSelectedIndex - 1);
        this.renderPaletteResults(input.value);
      } else if (event.key === 'Enter') {
        event.preventDefault();
        const cmd = list[this.paletteSelectedIndex];
        if (cmd) this.runPaletteCommand(cmd);
      }
    });
    overlay.addEventListener('click', (event) => {
      if (event.target === overlay) this.closeCommandPalette();
    });
    const opener = document.getElementById('palette-open');
    if (opener) opener.addEventListener('click', () => this.openCommandPalette());
  },

  // ===================== STEP PLAYBACK =====================

  startPlayback() {
    const items = document.querySelectorAll('#steps-container .step-item');
    if (items.length === 0) return;
    if (this._playbackTimer) this.stopPlayback();

    items.forEach(it => it.classList.add('dimmed'));
    this._playbackIndex = 0;
    this._setPlaybackPlaying(true);
    this._tickPlayback();
  },

  _tickPlayback() {
    const items = document.querySelectorAll('#steps-container .step-item');
    items.forEach(it => it.classList.remove('now-playing'));
    if (this._playbackIndex >= items.length) {
      this.stopPlayback(true);
      return;
    }
    const current = items[this._playbackIndex];
    current.classList.remove('dimmed');
    current.classList.add('now-playing');
    current.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    const fill = document.getElementById('steps-progress-fill');
    if (fill) fill.style.width = `${((this._playbackIndex + 1) / items.length) * 100}%`;

    const speed = parseInt(document.getElementById('playback-speed').value || '800', 10);
    this._playbackTimer = setTimeout(() => {
      this._playbackIndex++;
      this._tickPlayback();
    }, speed);
  },

  pausePlayback() {
    if (this._playbackTimer) {
      clearTimeout(this._playbackTimer);
      this._playbackTimer = null;
    }
    this._setPlaybackPlaying(false);
  },

  stopPlayback(reachedEnd) {
    if (this._playbackTimer) clearTimeout(this._playbackTimer);
    this._playbackTimer = null;
    this._playbackIndex = 0;
    document.querySelectorAll('#steps-container .step-item').forEach(it => {
      it.classList.remove('dimmed', 'now-playing');
    });
    const fill = document.getElementById('steps-progress-fill');
    if (fill) fill.style.width = reachedEnd ? '100%' : '0%';
    this._setPlaybackPlaying(false);
  },

  stepForwardPlayback() {
    const items = document.querySelectorAll('#steps-container .step-item');
    if (items.length === 0) return;
    if (this._playbackIndex === undefined) {
      items.forEach(it => it.classList.add('dimmed'));
      this._playbackIndex = 0;
    } else if (this._playbackTimer) {
      this.pausePlayback();
    }
    if (this._playbackIndex < items.length) {
      const cur = items[this._playbackIndex];
      cur.classList.remove('dimmed');
      cur.classList.add('now-playing');
      const fill = document.getElementById('steps-progress-fill');
      if (fill) fill.style.width = `${((this._playbackIndex + 1) / items.length) * 100}%`;
      this._playbackIndex++;
      setTimeout(() => cur.classList.remove('now-playing'), 600);
    }
  },

  _setPlaybackPlaying(playing) {
    const playIcon = document.querySelector('#playback-toggle .play-icon');
    const pauseIcon = document.querySelector('#playback-toggle .pause-icon');
    if (!playIcon || !pauseIcon) return;
    playIcon.classList.toggle('hidden', !!playing);
    pauseIcon.classList.toggle('hidden', !playing);
  },

  bindPlaybackControls() {
    const toggle = document.getElementById('playback-toggle');
    const stop = document.getElementById('playback-restart');
    const step = document.getElementById('playback-step');
    if (!toggle) return;
    toggle.addEventListener('click', () => {
      if (this._playbackTimer) this.pausePlayback();
      else this.startPlayback();
    });
    if (stop) stop.addEventListener('click', () => this.stopPlayback());
    if (step) step.addEventListener('click', () => this.stepForwardPlayback());
  },

  // ===================== EXPORT MODAL =====================

  openExportModal() {
    if (this.lastResult === null) {
      this.showError('Evaluate a formula first to export it.');
      return;
    }
    const overlay = document.getElementById('export-overlay');
    overlay.classList.remove('hidden');
    overlay.setAttribute('aria-hidden', 'false');
    this._exportFormat = 'latex';
    document.querySelectorAll('.export-tab').forEach(t => {
      t.classList.toggle('active', t.dataset.format === 'latex');
    });
    this.refreshExportOutput();
  },

  closeExportModal() {
    const overlay = document.getElementById('export-overlay');
    overlay.classList.add('hidden');
    overlay.setAttribute('aria-hidden', 'true');
  },

  refreshExportOutput() {
    const fmt = this._exportFormat || 'latex';
    const out = document.getElementById('export-output');
    if (!out) return;
    out.value = this.buildExportText(fmt);
  },

  buildExportText(fmt) {
    const formula = document.getElementById('formula-input').value.trim();
    const r = this.lastResult;
    if (r === null) return '';
    const m = this.m;
    const mod = polyStr(this.irr);

    if (fmt === 'latex') {
      const lines = [];
      lines.push(`% GF(2^${m}) computation`);
      lines.push(`% Modulus: ${mod}`);
      lines.push('');
      lines.push(`\\begin{aligned}`);
      lines.push(`  \\text{Field: } & \\mathrm{GF}(2^{${m}}) \\\\`);
      lines.push(`  \\text{Modulus: } & p(x) = ${this.polyToLatex(this.irr)} \\\\`);
      lines.push(`  \\text{Formula: } & ${this.formulaToLatex(formula)} \\\\`);
      lines.push(`  \\text{Result: } & ${this.polyToLatex(r)} \\\\`);
      lines.push(`  & = \\mathtt{${toBin(r)}_2} = \\mathtt{0x${toHex(r)}}`);
      lines.push(`\\end{aligned}`);
      return lines.join('\n');
    }

    if (fmt === 'markdown') {
      const lines = [];
      lines.push(`### GF(2^${m}) calculation`);
      lines.push('');
      lines.push(`- **Modulus**: $p(x) = ${this.polyToLatex(this.irr)}$`);
      lines.push(`- **Formula**: $${this.formulaToLatex(formula)}$`);
      lines.push(`- **Result**: $${this.polyToLatex(r)}$`);
      lines.push(`- **Bin**: \`${toBin(r)}\``);
      lines.push(`- **Hex**: \`0x${toHex(r)}\``);
      return lines.join('\n');
    }

    // plain text
    const lines = [];
    lines.push(`GF(2^${m}) calculation`);
    lines.push(`Modulus: p(x) = ${mod}`);
    lines.push(`Formula: ${formula}`);
    lines.push(`Result: ${polyStr(r)}`);
    lines.push(`  Bin: ${toBin(r)}`);
    lines.push(`  Hex: 0x${toHex(r)}`);
    return lines.join('\n');
  },

  polyToLatex(p) {
    if (p === 0n) return '0';
    const terms = [];
    const d = degree(p);
    for (let i = d; i >= 0; i--) {
      if (p & (1n << BigInt(i))) {
        if (i === 0) terms.push('1');
        else if (i === 1) terms.push('x');
        else terms.push(`x^{${i}}`);
      }
    }
    return terms.join(' + ');
  },

  formulaToLatex(formula) {
    if (!formula) return '?';
    return formula
      .replace(/\bxor\b/gi, ' \\oplus ')
      .replace(/\*/g, ' \\cdot ')
      .replace(/\//g, ' / ')
      .replace(/\binv\(/g, '(\\,')
      .replace(/\^(\d+)/g, '^{$1}');
  },

  bindExportModal() {
    const close = document.getElementById('export-close');
    const overlay = document.getElementById('export-overlay');
    const copy = document.getElementById('export-copy');
    if (close) close.addEventListener('click', () => this.closeExportModal());
    if (overlay) overlay.addEventListener('click', (event) => {
      if (event.target === overlay) this.closeExportModal();
    });
    document.querySelectorAll('.export-tab').forEach(tab => {
      tab.addEventListener('click', () => {
        document.querySelectorAll('.export-tab').forEach(t => t.classList.toggle('active', t === tab));
        this._exportFormat = tab.dataset.format;
        this.refreshExportOutput();
      });
    });
    if (copy) copy.addEventListener('click', async () => {
      const out = document.getElementById('export-output');
      try {
        await navigator.clipboard.writeText(out.value);
        copy.textContent = 'Copied ✓';
        setTimeout(() => copy.textContent = 'Copy to clipboard', 1200);
      } catch (e) {
        out.select();
      }
    });
  },

  // ===================== STICKY RESULT CHIP =====================

  bindStickyChip() {
    const chip = document.getElementById('sticky-chip');
    const valEl = document.getElementById('sticky-value');
    const result = document.getElementById('result-section');
    if (!chip || !result) return;

    chip.addEventListener('click', () => {
      result.scrollIntoView({ behavior: 'smooth', block: 'center' });
    });

    if (!('IntersectionObserver' in window)) return;
    const observer = new IntersectionObserver((entries) => {
      const e = entries[0];
      if (this.lastResult === null || result.classList.contains('hidden')) {
        chip.classList.add('hidden');
        return;
      }
      if (e.intersectionRatio < 0.1) {
        valEl.textContent = this.formatValue(this.lastResult, this.resultFormat) || polyStr(this.lastResult);
        chip.classList.remove('hidden');
      } else {
        chip.classList.add('hidden');
      }
    }, { threshold: [0, 0.1, 0.5] });
    observer.observe(result);
  },

  // ===================== FIELD TABLES (heatmap + discrete log) =====================

  renderFieldTables() {
    const container = document.getElementById('tables-container');
    if (!container) return;
    container.innerHTML = '';

    const heatmapMaxM = 5;
    const logMaxM = 12;

    if (this.m > heatmapMaxM && this.m > logMaxM) {
      const note = document.createElement('div');
      note.className = 'tables-empty';
      note.textContent = `Field tables aren't shown for m=${this.m}. Switch to a smaller field (m ≤ ${logMaxM}) to see them.`;
      container.appendChild(note);
      return;
    }

    if (this.m <= heatmapMaxM) {
      container.appendChild(this.buildHeatmap('mul'));
      container.appendChild(this.buildHeatmap('add'));
    } else {
      const note = document.createElement('div');
      note.className = 'tables-empty';
      note.textContent = `Heatmaps are shown for m ≤ ${heatmapMaxM} (m=${this.m} would have ${1 << this.m}×${1 << this.m} cells).`;
      container.appendChild(note);
    }

    if (this.m <= logMaxM) {
      container.appendChild(this.buildDiscreteLogPanel());
    }
  },

  buildHeatmap(kind) {
    const N = 1 << this.m;
    const wrap = document.createElement('div');
    wrap.className = 'op-heatmap';

    const header = document.createElement('div');
    header.className = 'op-heatmap-header';
    const title = document.createElement('div');
    title.className = 'op-heatmap-title';
    const sym = document.createElement('span');
    sym.className = 'op-symbol';
    sym.textContent = kind === 'mul' ? '×' : '⊕';
    title.append(sym);
    title.appendChild(document.createTextNode(kind === 'mul' ? 'Multiplication table (mod p)' : 'Addition / XOR table'));
    const hint = document.createElement('div');
    hint.className = 'op-heatmap-hint';
    hint.textContent = 'Click a cell to load A and B';
    header.append(title, hint);
    wrap.appendChild(header);

    const grid = document.createElement('div');
    grid.className = 'op-heatmap-grid';
    const size = N + 1; // +1 for header row/column
    grid.style.gridTemplateColumns = `repeat(${size}, minmax(14px, 1fr))`;

    for (let r = 0; r < size; r++) {
      for (let c = 0; c < size; c++) {
        const cell = document.createElement('div');
        cell.className = 'op-heatmap-cell';

        if (r === 0 && c === 0) {
          cell.classList.add('corner');
          cell.textContent = kind === 'mul' ? '×' : '⊕';
        } else if (r === 0) {
          cell.classList.add('header');
          cell.textContent = (c - 1).toString(16).toUpperCase();
        } else if (c === 0) {
          cell.classList.add('header');
          cell.textContent = (r - 1).toString(16).toUpperCase();
        } else {
          const a = BigInt(r - 1);
          const b = BigInt(c - 1);
          let v;
          if (kind === 'mul') {
            v = (a === 0n || b === 0n) ? 0n : reduceSimple(mulRaw(a, b), this.irr);
          } else {
            v = a ^ b;
          }
          const vNum = Number(v);
          cell.textContent = vNum.toString(16).toUpperCase();
          cell.title = `${a.toString(16).toUpperCase()} ${kind === 'mul' ? '×' : '⊕'} ${b.toString(16).toUpperCase()} = ${vNum.toString(16).toUpperCase()}  (poly: ${polyStr(v)})`;
          if (v === 0n) cell.classList.add('zero');
          // Color by value: hue rotation across full range
          const hue = (vNum / Math.max(N, 1)) * 320;
          const sat = v === 0n ? 0 : 70;
          const light = v === 0n ? 22 : 36;
          cell.style.backgroundColor = `hsl(${hue}, ${sat}%, ${light}%)`;
          cell.addEventListener('click', () => this.loadOperandsToVariables(a, b, kind));
        }
        grid.appendChild(cell);
      }
    }
    wrap.appendChild(grid);
    return wrap;
  },

  loadOperandsToVariables(a, b, kind) {
    const ensureVar = (name, format) => {
      if (!this.variableNames.includes(name)) this.addVariable(name, format);
      const row = this.getVariableRow(name);
      if (row && row.dataset.format !== format) this.setVariableFormat(name, format);
      const inp = this.getVariableValueInput(name);
      return inp;
    };
    const inpA = ensureVar('A', 'hex');
    const inpB = ensureVar('B', 'hex');
    inpA.value = a.toString(16).toUpperCase();
    inpB.value = b.toString(16).toUpperCase();
    this.updateVariablePreview('A');
    this.updateVariablePreview('B');
    document.getElementById('formula-input').value = kind === 'mul' ? 'A * B' : 'A xor B';
    this.recordFormulaHistory();
  },

  buildDiscreteLogPanel() {
    const wrap = document.createElement('div');
    wrap.className = 'log-panel';

    const N = (1n << BigInt(this.m)) - 1n;
    const factors = primeFactorsBigInt(N);
    const xOrder = orderOfX(this.m, this.irr, factors);
    let g, primFromX;
    if (xOrder === N) {
      g = 2n;
      primFromX = true;
    } else {
      g = findPrimitiveElement(this.m, this.irr, factors);
      primFromX = false;
    }

    const header = document.createElement('div');
    header.className = 'log-panel-header';
    const title = document.createElement('div');
    title.className = 'log-panel-title';
    title.textContent = 'Discrete log table';
    const info = document.createElement('div');
    info.className = 'log-panel-info';
    if (g === null) {
      info.textContent = 'no primitive element found in this field';
    } else {
      info.textContent = `g = ${polyStr(g)} (${primFromX ? 'x is primitive' : 'first primitive element'}), |F*| = ${N.toString()}`;
    }
    const search = document.createElement('input');
    search.type = 'text';
    search.className = 'log-search';
    search.placeholder = 'Find by hex, bin, or k...';
    search.autocomplete = 'off';
    header.append(title, info, search);
    wrap.appendChild(header);

    if (g === null) return wrap;

    // Build the table: gPow[k] = g^k for k = 0..N-1
    const grid = document.createElement('div');
    grid.className = 'log-grid';
    const entries = [];
    let power = 1n;
    for (let k = 0n; k < N; k++) {
      const valHex = power.toString(16).toUpperCase();
      const valPoly = polyStr(power);
      const entry = document.createElement('div');
      entry.className = 'log-entry';
      entry.dataset.hex = valHex;
      entry.dataset.bin = power.toString(2);
      entry.dataset.k = k.toString();
      entry.title = `g^${k} = ${valHex} (${valPoly})`;
      const keySpan = document.createElement('span');
      keySpan.className = 'log-key';
      keySpan.textContent = `g^${k}`;
      const arrow = document.createElement('span');
      arrow.className = 'log-arrow';
      arrow.textContent = '=';
      const valSpan = document.createElement('span');
      valSpan.className = 'log-value';
      valSpan.textContent = valHex.length <= 4 ? `${valHex}h ${valPoly}` : valHex + 'h';
      entry.append(keySpan, arrow, valSpan);
      entry.addEventListener('click', () => {
        this.loadOperandsToVariables(power, power, 'mul');
        document.getElementById('formula-input').value = 'A';
        this.updateFormulaPreview();
      });
      entries.push(entry);
      grid.appendChild(entry);
      power = reduceSimple(mulRaw(power, g), this.irr);
    }
    wrap.appendChild(grid);

    search.addEventListener('input', () => {
      const q = search.value.trim().toLowerCase();
      let visible = 0;
      for (const e of entries) {
        const matches = q === '' ||
          e.dataset.hex.toLowerCase().includes(q) ||
          e.dataset.bin.includes(q) ||
          ('g^' + e.dataset.k).includes(q) ||
          e.dataset.k === q;
        e.style.display = matches ? '' : 'none';
        if (matches) visible++;
      }
      info.textContent = q
        ? `${visible} match${visible === 1 ? '' : 'es'}`
        : `g = ${polyStr(g)} (${primFromX ? 'x is primitive' : 'first primitive element'}), |F*| = ${N.toString()}`;
    });

    return wrap;
  },

  // ===================== SHAREABLE URL =====================

  encodeShareState() {
    const state = {
      v: 1,
      m: this.m,
      irr: this.irr.toString(16),
      f: document.getElementById('formula-input').value,
      r: this.resultFormat,
      vars: this.variableNames.map(name => ({
        n: name,
        f: this.getVariableFormat(name),
        v: (this.getVariableValueInput(name) || { value: '' }).value
      }))
    };
    const json = JSON.stringify(state);
    const b64 = btoa(unescape(encodeURIComponent(json)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
    return b64;
  },

  decodeShareState(s) {
    try {
      let b64 = s.replace(/-/g, '+').replace(/_/g, '/');
      while (b64.length % 4) b64 += '=';
      const json = decodeURIComponent(escape(atob(b64)));
      return JSON.parse(json);
    } catch (e) {
      return null;
    }
  },

  shareWorkspace() {
    const code = this.encodeShareState();
    const url = `${window.location.origin}${window.location.pathname}#s=${code}`;
    const writeClipboard = (text) => {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        return navigator.clipboard.writeText(text);
      }
      // Fallback
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.left = '-9999px';
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand('copy'); } catch (e) {}
      document.body.removeChild(ta);
      return Promise.resolve();
    };
    writeClipboard(url).then(
      () => this.showShareToast('Link copied to clipboard'),
      () => {
        // If clipboard fails, just update the address bar
        try { window.history.replaceState({}, '', `#s=${code}`); } catch (e) {}
        this.showShareToast('Link is in the address bar');
      }
    );
    try { window.history.replaceState({}, '', `#s=${code}`); } catch (e) {}
  },

  showShareToast(msg) {
    const toast = document.getElementById('share-toast');
    if (!toast) return;
    toast.textContent = msg;
    toast.classList.add('visible');
    if (this._toastTimer) clearTimeout(this._toastTimer);
    this._toastTimer = setTimeout(() => toast.classList.remove('visible'), 1800);
  },

  loadFromUrlHash() {
    const hash = window.location.hash || '';
    const match = hash.match(/^#s=([A-Za-z0-9_\-]+)/);
    if (!match) return false;
    const data = this.decodeShareState(match[1]);
    if (!data) return false;
    this.applyState({
      m: data.m,
      irrHex: data.irr,
      formula: data.f,
      resultFormat: data.r,
      variables: Array.isArray(data.vars)
        ? data.vars.map(v => ({ name: v.n, format: v.f, value: v.v }))
        : []
    });
    return true;
  }

};

// ===================== INIT =====================

document.addEventListener('DOMContentLoaded', () => App.init());
