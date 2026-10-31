(function () {
  const V_SPECS = [
    null,
    { total: 26, data: 19, ec: 7, b1: 1, d1: 19, b2: 0, d2: 0, align: [] },
    { total: 44, data: 34, ec: 10, b1: 1, d1: 34, b2: 0, d2: 0, align: [6, 18] },
    { total: 70, data: 55, ec: 15, b1: 1, d1: 55, b2: 0, d2: 0, align: [6, 22] },
    { total: 100, data: 80, ec: 20, b1: 1, d1: 80, b2: 0, d2: 0, align: [6, 26] },
    { total: 134, data: 108, ec: 26, b1: 1, d1: 108, b2: 0, d2: 0, align: [6, 30] },
    { total: 172, data: 136, ec: 18, b1: 2, d1: 68, b2: 0, d2: 0, align: [6, 34] },
    { total: 196, data: 156, ec: 20, b1: 2, d1: 78, b2: 0, d2: 0, align: [6, 22, 38] },
    { total: 242, data: 194, ec: 24, b1: 2, d1: 97, b2: 0, d2: 0, align: [6, 24, 42] },
    { total: 292, data: 232, ec: 30, b1: 2, d1: 116, b2: 0, d2: 0, align: [6, 26, 46] },
    { total: 346, data: 274, ec: 18, b1: 2, d1: 68, b2: 2, d2: 69, align: [6, 28, 50] }
  ];

  const GF_EXP = new Uint8Array(512);
  const GF_LOG = new Uint8Array(256);
  (function initGf() {
    let x = 1;
    for (let i = 0; i < 255; i++) {
      GF_EXP[i] = x;
      GF_LOG[x] = i;
      x <<= 1;
      if (x & 0x100) x ^= 0x11d;
    }
    for (let i = 255; i < 512; i++) {
      GF_EXP[i] = GF_EXP[i - 255];
    }
  })();

  function gfMul(a, b) {
    if (a === 0 || b === 0) return 0;
    return GF_EXP[GF_LOG[a] + GF_LOG[b]];
  }

  function rsGeneratorPoly(degree) {
    let poly = new Uint8Array([1]);
    for (let i = 0; i < degree; i++) {
      const next = new Uint8Array(poly.length + 1);
      const factor = GF_EXP[i];
      for (let j = 0; j < poly.length; j++) {
        next[j] ^= poly[j];
        next[j + 1] ^= gfMul(poly[j], factor);
      }
      poly = next;
    }
    return poly;
  }

  function rsEncode(dataBytes, ecLen) {
    const gen = rsGeneratorPoly(ecLen);
    const rem = new Uint8Array(ecLen);
    for (let i = 0; i < dataBytes.length; i++) {
      const factor = dataBytes[i] ^ rem[0];
      rem.copyWithin(0, 1);
      rem[ecLen - 1] = 0;
      if (factor !== 0) {
        for (let j = 0; j < ecLen; j++) {
          rem[j] ^= gfMul(gen[j + 1], factor);
        }
      }
    }
    return rem;
  }

  function encodeMatrix(text) {
    const utf8 = new TextEncoder().encode(String(text || ''));
    let version = 1;
    while (version <= 10) {
      const cap = V_SPECS[version].data - (version <= 9 ? 2 : 3);
      if (utf8.length <= cap) break;
      version++;
    }
    if (version > 10) version = 10;
    const spec = V_SPECS[version];
    const maxPayload = spec.data - (version <= 9 ? 2 : 3);
    const bytes = utf8.length > maxPayload ? utf8.slice(0, maxPayload) : utf8;

    const bits = [];
    const pushBits = (val, len) => {
      for (let i = len - 1; i >= 0; i--) {
        bits.push((val >>> i) & 1);
      }
    };

    pushBits(0b0100, 4);
    pushBits(bytes.length, version <= 9 ? 8 : 16);
    for (let i = 0; i < bytes.length; i++) {
      pushBits(bytes[i], 8);
    }

    const maxBits = spec.data * 8;
    const terminator = Math.min(4, maxBits - bits.length);
    pushBits(0, terminator);
    while (bits.length % 8 !== 0) bits.push(0);

    const dataCodewords = new Uint8Array(spec.data);
    for (let i = 0; i < bits.length / 8; i++) {
      let b = 0;
      for (let j = 0; j < 8; j++) {
        b = (b << 1) | bits[i * 8 + j];
      }
      dataCodewords[i] = b;
    }
    const padBytes = [0xec, 0x11];
    let padIdx = 0;
    for (let i = bits.length / 8; i < spec.data; i++) {
      dataCodewords[i] = padBytes[padIdx % 2];
      padIdx++;
    }

    const blocks = [];
    const ecBlocks = [];
    let offset = 0;
    for (let b = 0; b < spec.b1; b++) {
      const slice = dataCodewords.slice(offset, offset + spec.d1);
      offset += spec.d1;
      blocks.push(slice);
      ecBlocks.push(rsEncode(slice, spec.ec));
    }
    for (let b = 0; b < spec.b2; b++) {
      const slice = dataCodewords.slice(offset, offset + spec.d2);
      offset += spec.d2;
      blocks.push(slice);
      ecBlocks.push(rsEncode(slice, spec.ec));
    }

    const interleaved = [];
    const maxDataLen = Math.max(spec.d1, spec.d2);
    for (let i = 0; i < maxDataLen; i++) {
      for (let b = 0; b < blocks.length; b++) {
        if (i < blocks[b].length) interleaved.push(blocks[b][i]);
      }
    }
    for (let i = 0; i < spec.ec; i++) {
      for (let b = 0; b < ecBlocks.length; b++) {
        interleaved.push(ecBlocks[b][i]);
      }
    }

    const size = 17 + version * 4;
    const matrix = Array.from({ length: size }, () => new Uint8Array(size));
    const reserved = Array.from({ length: size }, () => new Uint8Array(size));

    const setModule = (r, c, dark, isReserved) => {
      if (r < 0 || r >= size || c < 0 || c >= size) return;
      matrix[r][c] = dark ? 1 : 0;
      if (isReserved) reserved[r][c] = 1;
    };

    const placeFinder = (top, left) => {
      for (let r = -1; r <= 7; r++) {
        for (let c = -1; c <= 7; c++) {
          const inOuter = r >= 0 && r <= 6 && c >= 0 && c <= 6;
          const onBorder = r === 0 || r === 6 || c === 0 || c === 6;
          const inCore = r >= 2 && r <= 4 && c >= 2 && c <= 4;
          setModule(top + r, left + c, inOuter && (onBorder || inCore), true);
        }
      }
    };

    placeFinder(0, 0);
    placeFinder(0, size - 7);
    placeFinder(size - 7, 0);

    for (let i = 8; i < size - 8; i++) {
      setModule(6, i, i % 2 === 0, true);
      setModule(i, 6, i % 2 === 0, true);
    }

    const align = spec.align;
    for (let i = 0; i < align.length; i++) {
      for (let j = 0; j < align.length; j++) {
        const ar = align[i];
        const ac = align[j];
        if (reserved[ar][ac]) continue;
        for (let r = -2; r <= 2; r++) {
          for (let c = -2; c <= 2; c++) {
            const dark = Math.max(Math.abs(r), Math.abs(c)) !== 1;
            setModule(ar + r, ac + c, dark, true);
          }
        }
      }
    }

    for (let i = 0; i < 9; i++) {
      if (i !== 6) {
        reserved[8][i] = 1;
        reserved[i][8] = 1;
      }
    }
    for (let i = 0; i < 8; i++) {
      reserved[8][size - 1 - i] = 1;
      reserved[size - 1 - i][8] = 1;
    }
    setModule(size - 8, 8, true, true);

    const streamBits = [];
    for (let i = 0; i < interleaved.length; i++) {
      for (let b = 7; b >= 0; b--) {
        streamBits.push((interleaved[i] >>> b) & 1);
      }
    }

    let bitIdx = 0;
    let upward = true;
    for (let right = size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (let vert = 0; vert < size; vert++) {
        const r = upward ? size - 1 - vert : vert;
        for (let j = 0; j < 2; j++) {
          const c = right - j;
          if (!reserved[r][c]) {
            const dark = bitIdx < streamBits.length ? streamBits[bitIdx] === 1 : false;
            matrix[r][c] = dark ? 1 : 0;
            bitIdx++;
          }
        }
      }
      upward = !upward;
    }

    for (let r = 0; r < size; r++) {
      for (let c = 0; c < size; c++) {
        if (!reserved[r][c] && (r + c) % 2 === 0) {
          matrix[r][c] ^= 1;
        }
      }
    }

    const formatBits = 0x77c4;
    for (let i = 0; i <= 5; i++) setModule(8, i, ((formatBits >>> i) & 1) === 1, true);
    setModule(8, 7, ((formatBits >>> 6) & 1) === 1, true);
    setModule(8, 8, ((formatBits >>> 7) & 1) === 1, true);
    setModule(7, 8, ((formatBits >>> 8) & 1) === 1, true);
    for (let i = 9; i < 15; i++) setModule(14 - i, 8, ((formatBits >>> i) & 1) === 1, true);

    for (let i = 0; i < 8; i++) setModule(size - 1 - i, 8, ((formatBits >>> i) & 1) === 1, true);
    for (let i = 8; i < 15; i++) setModule(8, size - 15 + i, ((formatBits >>> i) & 1) === 1, true);

    return matrix;
  }

  function toSvgString(text, pixelSize) {
    const sizePx = pixelSize || 240;
    const matrix = encodeMatrix(text);
    const n = matrix.length;
    const margin = 2;
    const total = n + margin * 2;
    let path = '';
    for (let r = 0; r < n; r++) {
      for (let c = 0; c < n; c++) {
        if (matrix[r][c]) {
          path += `M${c + margin},${r + margin}h1v1h-1z`;
        }
      }
    }
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${total} ${total}" width="${sizePx}" height="${sizePx}" shape-rendering="crispEdges"><rect width="${total}" height="${total}" fill="#ffffff"/><path d="${path}" fill="#000000"/></svg>`;
  }

  function toSvgDataUrl(text, pixelSize) {
    const svg = toSvgString(text, pixelSize);
    return `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`;
  }

  function toPngDataUrl(text, pixelSize) {
    try {
      const sizePx = pixelSize || 240;
      const matrix = encodeMatrix(text);
      const n = matrix.length;
      const margin = 2;
      const total = n + margin * 2;
      const scale = Math.max(4, Math.floor(sizePx / total));
      const canvasSize = total * scale;
      const canvas = document.createElement('canvas');
      canvas.width = canvasSize;
      canvas.height = canvasSize;
      const ctx = canvas.getContext('2d');
      if (!ctx) return toSvgDataUrl(text, sizePx);
      ctx.fillStyle = '#ffffff';
      ctx.fillRect(0, 0, canvasSize, canvasSize);
      ctx.fillStyle = '#000000';
      for (let r = 0; r < n; r++) {
        for (let c = 0; c < n; c++) {
          if (matrix[r][c]) {
            ctx.fillRect((c + margin) * scale, (r + margin) * scale, scale, scale);
          }
        }
      }
      return canvas.toDataURL('image/png');
    } catch {
      return toSvgDataUrl(text, pixelSize);
    }
  }

  function applyQrToElements(urlText, imgEl, downloadAnchorEl, filename) {
    const dataUrl = toPngDataUrl(urlText, 240);
    if (imgEl) {
      imgEl.src = dataUrl;
    }
    if (downloadAnchorEl) {
      downloadAnchorEl.href = dataUrl;
      if (filename) downloadAnchorEl.download = filename;
    }
    return dataUrl;
  }

  function createFocusTrap(modalEl, onClose) {
    let previousTrigger = null;

    function getFocusable() {
      const selector =
        'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
      return Array.from(modalEl.querySelectorAll(selector)).filter(
        (el) => el.offsetParent !== null || el === document.activeElement
      );
    }

    function onKeyDown(e) {
      if (!modalEl.classList.contains('active')) return;
      if (e.key === 'Escape') {
        e.preventDefault();
        if (onClose) onClose();
        return;
      }
      if (e.key === 'Tab') {
        const focusable = getFocusable();
        if (focusable.length === 0) {
          e.preventDefault();
          return;
        }
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (e.shiftKey) {
          if (document.activeElement === first || !modalEl.contains(document.activeElement)) {
            e.preventDefault();
            last.focus();
          }
        } else {
          if (document.activeElement === last || !modalEl.contains(document.activeElement)) {
            e.preventDefault();
            first.focus();
          }
        }
      }
    }

    document.addEventListener('keydown', onKeyDown);

    return {
      activate(triggerEl) {
        previousTrigger = triggerEl || document.activeElement;
        requestAnimationFrame(() => {
          const focusable = getFocusable();
          if (focusable.length > 0) focusable[0].focus();
        });
      },
      deactivate() {
        if (previousTrigger && typeof previousTrigger.focus === 'function') {
          previousTrigger.focus();
        }
        previousTrigger = null;
      }
    };
  }

  function initReportModal(options) {
    const showToast = (options && options.showToast) || function () {};
    const showInlineError = (options && options.showInlineError) || function () {};
    const modal = document.getElementById('reportModal');
    const openBtns = document.querySelectorAll('[data-open-report]');
    const closeBtn = document.getElementById('reportModalClose');
    const cancelBtn = document.getElementById('reportModalCancel');
    const form = document.getElementById('reportForm');
    const targetInput = document.getElementById('reportTargetUrl');
    const categoryInput = document.getElementById('reportCategory');
    const explanationInput = document.getElementById('reportExplanation');
    const nameInput = document.getElementById('reportNotifierName');
    const emailInput = document.getElementById('reportNotifierEmail');
    const faithInput = document.getElementById('reportGoodFaith');
    const submitBtn = document.getElementById('reportSubmitBtn');
    const statusBox = document.getElementById('reportFormStatus');

    if (!modal || !form) return { openReportModal: function () {} };

    function closeModal() {
      modal.classList.remove('active');
      modal.setAttribute('aria-hidden', 'true');
      trap.deactivate();
    }

    const trap = createFocusTrap(modal, closeModal);

    function openModal(prefillUrl, triggerEl) {
      if (targetInput) {
        targetInput.value = prefillUrl || window.location.href;
      }
      if (statusBox) {
        statusBox.textContent = '';
        statusBox.className = 'report-status';
      }
      modal.classList.add('active');
      modal.setAttribute('aria-hidden', 'false');
      trap.activate(triggerEl);
    }

    openBtns.forEach((btn) => {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        const customUrl = btn.getAttribute('data-report-url') || window.location.href;
        openModal(customUrl, btn);
      });
    });

    if (closeBtn) closeBtn.addEventListener('click', closeModal);
    if (cancelBtn) cancelBtn.addEventListener('click', closeModal);
    modal.addEventListener('click', (e) => {
      if (e.target === modal) closeModal();
    });

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const payload = {
        targetUrl: targetInput ? targetInput.value.trim() : window.location.href,
        category: categoryInput ? categoryInput.value : 'illegal_content',
        explanation: explanationInput ? explanationInput.value.trim() : '',
        notifierName: nameInput ? nameInput.value.trim() : '',
        notifierEmail: emailInput ? emailInput.value.trim() : '',
        goodFaithConfirmed: Boolean(faithInput && faithInput.checked)
      };

      if (!payload.targetUrl || !payload.explanation || !payload.goodFaithConfirmed) {
        if (statusBox) {
          statusBox.textContent = 'Please complete all required fields and confirm good faith.';
          statusBox.className = 'report-status error';
        }
        return;
      }

      if (submitBtn) submitBtn.disabled = true;
      try {
        const res = await fetch('/api/report', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Requested-With': 'sera.drop'
          },
          body: JSON.stringify(payload)
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          const msg = data.error || 'Failed to submit abuse report.';
          if (statusBox) {
            statusBox.textContent = msg;
            statusBox.className = 'report-status error';
          }
          showInlineError(msg);
          return;
        }
        form.reset();
        closeModal();
        showToast('Report submitted');
      } catch {
        const msg = 'Network error while submitting report.';
        if (statusBox) {
          statusBox.textContent = msg;
          statusBox.className = 'report-status error';
        }
        showInlineError(msg);
      } finally {
        if (submitBtn) submitBtn.disabled = false;
      }
    });

    return { openReportModal: openModal, closeReportModal: closeModal };
  }

  window.SeraQR = {
    encodeMatrix,
    toSvgString,
    toSvgDataUrl,
    toPngDataUrl,
    applyQrToElements,
    createFocusTrap,
    initReportModal
  };
})();
