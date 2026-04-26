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

// ===================== FORMULA PARSER =====================

function tokenizeFormula(str) {
  const tokens = [];
  let i = 0;

  while (i < str.length) {
    const ch = str[i];

    if (/\s/.test(ch)) {
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

    if (/[01]/.test(ch)) {
      let j = i;
      while (j < str.length && /[01]/.test(str[j])) j++;
      tokens.push({ type: 'number', value: str.slice(i, j) });
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
  let node = this.parseUnary();

  while (this.peek() && ['*', '/'].includes(this.peek().type)) {
    const op = this.peek().type;
    this.pos++;
    const right = this.parseUnary();
    node = this.applyBinary(op, node, right);
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

// ===================== UI CONTROLLER =====================

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

  init() {
    this.buildDegreeSelectors();
    this.addVariable('A');
    this.addVariable('B');
    this.addVariable('C');
    this.bindEvents();
    this.buildModulusOptions();
    this.updateIrreducibleDisplay();
    this.updatePlaceholders();
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

  addVariable(preferredName, preferredFormat = 'bin') {
    const list = document.getElementById('variables-list');
    const name = preferredName || this.nextVariableName();
    if (this.variableNames.includes(name)) return;

    this.variableNames.push(name);

    const row = document.createElement('div');
    row.className = 'variable-row';
    row.dataset.name = name;
    row.dataset.format = preferredFormat;

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

    row.append(nameInput, formatToggle, valueInput, preview, error, remove);
    list.appendChild(row);

    this.updatePlaceholders();
    this.updateFormulaToolbar();
    this.updateVariablePreview(name);
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
      return;
    }

    const val = this.parseInput(str, fmt);
    if (val === -1n) {
      preview.textContent = '';
      if (fmt === 'bin') error.textContent = 'Invalid: use 0 and 1';
      else if (fmt === 'hex') error.textContent = 'Invalid: use 0-9 and A-F';
      else error.textContent = 'Invalid polynomial';
      return;
    }

    if (val === null) {
      preview.textContent = 'Empty';
      preview.style.color = 'var(--text-muted)';
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
      preview.textContent = `Formula: ${formatFormulaDisplay(formula)}`;
      preview.style.color = 'var(--cyan)';
    } catch (err) {
      preview.textContent = '';
      error.textContent = err.message;
    }
  },

  hideResults() {
    document.getElementById('result-section').classList.add('hidden');
    document.getElementById('steps-section').classList.add('hidden');
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
        { label: 'Final Result', text: `${toBin(output.value, this.m)}  =  ${polyStr(output.value)}`, highlight: true }
      ];

      this.showResult(output.value, 'formula');
      this.showSteps(steps);
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

    // Primary display based on selected result format
    if (this.resultFormat === 'bin') {
      valEl.textContent = toBin(val, this.m);
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
  }
};

// ===================== INIT =====================

document.addEventListener('DOMContentLoaded', () => App.init());
