(function () {
  const mainContent = document.getElementById('mainContent');
  const toast = document.getElementById('toast');
  const inlineError = document.getElementById('inlineError');
  const inlineErrorText = document.getElementById('inlineErrorText');
  const inlineErrorDismiss = document.getElementById('inlineErrorDismiss');

  let toastTimer = null;
  function showToast(msg) {
    if (!toast) return;
    toast.textContent = msg;
    toast.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove('show'), 2400);
  }

  function showInlineError(msg) {
    if (!inlineError || !inlineErrorText) return;
    inlineErrorText.textContent = msg;
    inlineError.classList.add('active');
  }

  function clearInlineError() {
    if (!inlineError || !inlineErrorText) return;
    inlineErrorText.textContent = '';
    inlineError.classList.remove('active');
  }

  if (inlineErrorDismiss) {
    inlineErrorDismiss.addEventListener('click', clearInlineError);
  }

  const reportModalCtrl = window.SeraQR
    ? window.SeraQR.initReportModal({ showToast, showInlineError })
    : { openReportModal: function () {} };

  function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  function formatDate(iso) {
    const d = new Date(iso);
    return d.toLocaleString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  async function copyText(text, label = 'Link') {
    try {
      await navigator.clipboard.writeText(text);
      showToast(`${label} copied`);
    } catch {
      const input = document.createElement('input');
      input.value = text;
      document.body.appendChild(input);
      input.select();
      document.execCommand('copy');
      document.body.removeChild(input);
      showToast(`${label} copied`);
    }
  }

  function createPanZoomController({ stage, img, zoomLabel, onDoubleClick }) {
    let scale = 1;
    let panX = 0;
    let panY = 0;
    let isDragging = false;
    let startX = 0;
    let startY = 0;

    function updateTransform() {
      img.style.transform = `translate(calc(-50% + ${panX}px), calc(-50% + ${panY}px)) scale(${scale})`;
      if (zoomLabel) {
        zoomLabel.textContent = `${Math.round(scale * 100)}%`;
      }
    }

    function computeFitScale() {
      const nw = img.naturalWidth || 1;
      const nh = img.naturalHeight || 1;
      img.style.width = `${nw}px`;
      img.style.height = `${nh}px`;
      const sw = stage.clientWidth || 700;
      const sh = stage.clientHeight || 520;
      const pad = 24;
      const scaleX = Math.max(50, sw - pad) / nw;
      const scaleY = Math.max(50, sh - pad) / nh;
      return Math.min(scaleX, scaleY, 1);
    }

    function fitToStage() {
      scale = computeFitScale();
      panX = 0;
      panY = 0;
      updateTransform();
    }

    function setOriginalResolution() {
      if (img.naturalWidth && img.naturalHeight) {
        img.style.width = `${img.naturalWidth}px`;
        img.style.height = `${img.naturalHeight}px`;
      }
      scale = 1;
      panX = 0;
      panY = 0;
      updateTransform();
    }

    function zoomBy(factor, clientX, clientY) {
      const prevScale = scale;
      const nextScale = Math.min(Math.max(scale * factor, 0.05), 12);
      if (clientX !== undefined && clientY !== undefined) {
        const rect = stage.getBoundingClientRect();
        const cx = clientX - (rect.left + rect.width / 2);
        const cy = clientY - (rect.top + rect.height / 2);
        const ratio = nextScale / prevScale;
        panX = cx - (cx - panX) * ratio;
        panY = cy - (cy - panY) * ratio;
      }
      scale = nextScale;
      updateTransform();
    }

    stage.addEventListener(
      'wheel',
      (e) => {
        e.preventDefault();
        const factor = e.deltaY < 0 ? 1.18 : 1 / 1.18;
        zoomBy(factor, e.clientX, e.clientY);
      },
      { passive: false }
    );

    stage.addEventListener('mousedown', (e) => {
      if (e.button !== 0) return;
      isDragging = true;
      startX = e.clientX - panX;
      startY = e.clientY - panY;
      stage.classList.add('dragging');
    });

    window.addEventListener('mousemove', (e) => {
      if (!isDragging) return;
      panX = e.clientX - startX;
      panY = e.clientY - startY;
      updateTransform();
    });

    window.addEventListener('mouseup', () => {
      if (isDragging) {
        isDragging = false;
        stage.classList.remove('dragging');
      }
    });

    stage.addEventListener(
      'touchstart',
      (e) => {
        if (e.touches.length === 1) {
          isDragging = true;
          startX = e.touches[0].clientX - panX;
          startY = e.touches[0].clientY - panY;
        }
      },
      { passive: true }
    );

    stage.addEventListener(
      'touchmove',
      (e) => {
        if (!isDragging || e.touches.length !== 1) return;
        panX = e.touches[0].clientX - startX;
        panY = e.touches[0].clientY - startY;
        updateTransform();
      },
      { passive: true }
    );

    stage.addEventListener('touchend', () => {
      isDragging = false;
    });

    stage.addEventListener('dblclick', (e) => {
      if (onDoubleClick) {
        onDoubleClick(e);
        return;
      }
      const fit = computeFitScale();
      if (Math.abs(scale - 1) < 0.05 && fit < 0.98) {
        fitToStage();
      } else {
        const prevScale = scale;
        scale = 1;
        const rect = stage.getBoundingClientRect();
        const cx = e.clientX - (rect.left + rect.width / 2);
        const cy = e.clientY - (rect.top + rect.height / 2);
        const ratio = scale / prevScale;
        panX = cx - (cx - panX) * ratio;
        panY = cy - (cy - panY) * ratio;
        updateTransform();
      }
    });

    return {
      fitToStage,
      setOriginalResolution,
      zoomIn: () => zoomBy(1.25),
      zoomOut: () => zoomBy(1 / 1.25),
      getScale: () => scale
    };
  }

  const lightboxOverlay = document.getElementById('lightboxOverlay');
  const lightboxStage = document.getElementById('lightboxStage');
  const lightboxImg = document.getElementById('lightboxImg');
  const lbFileName = document.getElementById('lbFileName');
  const lbResolution = document.getElementById('lbResolution');
  const lbZoomLevel = document.getElementById('lbZoomLevel');
  const lbZoomIn = document.getElementById('lbZoomIn');
  const lbZoomOut = document.getElementById('lbZoomOut');
  const lbFitBtn = document.getElementById('lbFitBtn');
  const lbOriginalBtn = document.getElementById('lbOriginalBtn');
  const lbRawLink = document.getElementById('lbRawLink');
  const lbCloseBtn = document.getElementById('lbCloseBtn');

  const lbController = createPanZoomController({
    stage: lightboxStage,
    img: lightboxImg,
    zoomLabel: lbZoomLevel
  });

  const lightboxTrap = window.SeraQR
    ? window.SeraQR.createFocusTrap(lightboxOverlay, closeFullscreenViewer)
    : { activate: function () {}, deactivate: function () {} };

  lbZoomIn.addEventListener('click', () => lbController.zoomIn());
  lbZoomOut.addEventListener('click', () => lbController.zoomOut());
  lbFitBtn.addEventListener('click', () => lbController.fitToStage());
  lbOriginalBtn.addEventListener('click', () => lbController.setOriginalResolution());

  async function openFullscreenViewer(file, startInOriginalResolution = false, triggerEl = null) {
    lbFileName.textContent = file.originalName;
    lbRawLink.href = file.rawUrl;
    lightboxImg.src = file.rawUrl;
    lightboxOverlay.classList.add('active');
    lightboxOverlay.setAttribute('aria-hidden', 'false');
    lightboxTrap.activate(triggerEl);

    if (!document.fullscreenElement && lightboxOverlay.requestFullscreen) {
      try {
        await lightboxOverlay.requestFullscreen();
      } catch {}
    }

    const applyInitialZoom = () => {
      lbResolution.textContent = `${lightboxImg.naturalWidth} × ${lightboxImg.naturalHeight}`;
      if (startInOriginalResolution) {
        lbController.setOriginalResolution();
      } else {
        lbController.fitToStage();
      }
    };

    if (lightboxImg.complete && lightboxImg.naturalWidth) {
      requestAnimationFrame(applyInitialZoom);
    } else {
      lightboxImg.onload = () => requestAnimationFrame(applyInitialZoom);
    }
  }

  async function closeFullscreenViewer() {
    lightboxOverlay.classList.remove('active');
    lightboxOverlay.setAttribute('aria-hidden', 'true');
    lightboxTrap.deactivate();
    if (document.fullscreenElement && document.exitFullscreen) {
      try {
        await document.exitFullscreen();
      } catch {}
    }
  }

  lbCloseBtn.addEventListener('click', closeFullscreenViewer);

  document.addEventListener('fullscreenchange', () => {
    if (!document.fullscreenElement && lightboxOverlay.classList.contains('active')) {
      lightboxOverlay.classList.remove('active');
      lightboxOverlay.setAttribute('aria-hidden', 'true');
      lightboxTrap.deactivate();
    }
  });

  window.addEventListener('keydown', (e) => {
    if (!lightboxOverlay.classList.contains('active')) return;
    if (e.key === '+' || e.key === '=') {
      lbController.zoomIn();
    } else if (e.key === '-') {
      lbController.zoomOut();
    } else if (e.key === '1') {
      lbController.setOriginalResolution();
    } else if (e.key === '0') {
      lbController.fitToStage();
    }
  });

  async function loadSharedFile() {
    const pathParts = window.location.pathname.split('/').filter(Boolean);
    const code = pathParts[pathParts.length - 1];

    try {
      const res = await fetch(`/api/files/${encodeURIComponent(code)}`);
      if (!res.ok) {
        showInlineError('The requested file does not exist or has expired.');
        mainContent.innerHTML = `
          <div class="card empty-card-panel">
            <h2 class="empty-card-title">Not Found</h2>
            <p class="empty-card-desc">
              File does not exist or has expired.
            </p>
            <a href="/" class="btn btn-primary">Upload</a>
          </div>
        `;
        return;
      }

      const file = await res.json();
      document.title = `${file.originalName} — sera.drop`;

      const dedupePill = file.deduplicated
        ? `<span class="meta-pill pill-mono">Deduplicated</span>`
        : '';
      const ttlPill = file.expiresAt
        ? `<span class="meta-pill pill-crimson">Expires ${escapeHtml(formatDate(file.expiresAt))}</span>`
        : `<span class="meta-pill">Permanent</span>`;
      const signedPill = file.requireSignedUrl
        ? `<span class="meta-pill pill-crimson">Signed</span>`
        : '';
      const shaLine = file.sha256 ? `<div class="sha-line">${escapeHtml(file.sha256)}</div>` : '';

      mainContent.innerHTML = `
        <div class="share-grid">
          <div class="card">
            <div class="share-header-row">
              <div class="share-header-info">
                <div class="result-badges">
                  <span class="meta-pill">${escapeHtml(file.mimeType)}</span>
                  ${ttlPill}
                  ${dedupePill}
                  ${signedPill}
                </div>
                <h1 class="share-file-title">${escapeHtml(file.originalName)}</h1>
                <div class="file-sub">
                  <span>${escapeHtml(formatBytes(file.size))}</span>
                  <span>${escapeHtml(formatDate(file.createdAt))}</span>
                  <span><strong id="downloadCount">${Number(file.downloads) || 0}</strong> dl</span>
                </div>
                ${shaLine}
              </div>
              <div class="share-header-actions">
                <a href="${escapeHtml(file.downloadUrl)}" id="downloadBtn" class="btn btn-primary btn-lg">Download</a>
                <button type="button" id="shareReportBtn" class="btn btn-danger btn-sm">Report Abuse</button>
              </div>
            </div>

            <div id="previewContainer" class="preview-box"></div>
          </div>

          <aside class="card share-sidebar">
            <div>
              <div class="sidebar-label">Share</div>
              <div class="short-link-box">
                <input type="text" id="shortUrlInput" class="short-link-input" value="${escapeHtml(file.shortUrl)}" readonly />
              </div>
              <button type="button" id="copyBtn" class="btn btn-primary full-width-btn">Copy</button>
            </div>

            <div class="sidebar-section">
              <div class="sidebar-label">Direct</div>
              <div class="short-link-box">
                <input type="text" id="directUrlInput" class="short-link-input" value="${escapeHtml(file.directUrl || file.rawUrl)}" readonly />
              </div>
              <button type="button" id="copyDirectBtn" class="btn btn-secondary full-width-btn">Copy Direct</button>
            </div>

            <div class="sidebar-section qr-sidebar-section">
              <div class="qr-box qr-box-inline">
                <img id="shareQrImg" src="" alt="QR Code" class="qr-img-md" />
              </div>
              <div class="qr-save-row">
                <a id="shareQrSaveLink" href="#" download="qr-${escapeHtml(file.code)}.png" class="btn btn-secondary btn-sm full-width-btn">Save QR</a>
              </div>
            </div>
          </aside>
        </div>
      `;

      const shareQrImg = document.getElementById('shareQrImg');
      const shareQrSaveLink = document.getElementById('shareQrSaveLink');
      if (window.SeraQR) {
        window.SeraQR.applyQrToElements(
          file.shortUrl || window.location.href,
          shareQrImg,
          shareQrSaveLink,
          `qr-${file.code}.png`
        );
      } else if (file.qrCodeDataUrl) {
        shareQrImg.src = file.qrCodeDataUrl;
        shareQrSaveLink.href = file.qrCodeDataUrl;
      }

      const shortInput = document.getElementById('shortUrlInput');
      const directInput = document.getElementById('directUrlInput');
      shortInput.addEventListener('click', () => copyText(file.shortUrl, 'Share link'));
      shortInput.addEventListener('auxclick', (e) => {
        if (e.button === 1) window.open(file.shortUrl, '_blank', 'noopener,noreferrer');
      });
      directInput.addEventListener('click', () => copyText(file.directUrl || file.rawUrl, 'Direct link'));
      directInput.addEventListener('auxclick', (e) => {
        if (e.button === 1) window.open(file.directUrl || file.rawUrl, '_blank', 'noopener,noreferrer');
      });

      document.getElementById('copyBtn').addEventListener('click', () => copyText(file.shortUrl, 'Share link'));
      document
        .getElementById('copyDirectBtn')
        .addEventListener('click', () => copyText(file.directUrl || file.rawUrl, 'Direct link'));
      document.getElementById('downloadBtn').addEventListener('click', () => {
        const countEl = document.getElementById('downloadCount');
        if (countEl) {
          countEl.textContent = String(parseInt(countEl.textContent || '0', 10) + 1);
        }
      });

      const shareReportBtn = document.getElementById('shareReportBtn');
      if (shareReportBtn) {
        shareReportBtn.addEventListener('click', () => {
          reportModalCtrl.openReportModal(file.shortUrl || window.location.href, shareReportBtn);
        });
      }

      renderPreview(file, document.getElementById('previewContainer'));
    } catch (err) {
      showInlineError('Network error while loading shared file.');
      console.error(err);
    }
  }

  async function renderPreview(file, container) {
    const cat = file.previewCategory;
    const safeRawUrl = escapeHtml(file.rawUrl);
    const safeName = escapeHtml(file.originalName);
    if (cat === 'image') {
      container.innerHTML = `
        <div class="image-preview-wrapper">
          <div class="image-toolbar">
            <span id="inlineResBadge" class="image-res-badge">...</span>
            <div class="image-toolbar-actions">
              <button type="button" id="inlineZoomOut" class="btn btn-secondary btn-sm">−</button>
              <span id="inlineZoomLabel" class="zoom-indicator">100%</span>
              <button type="button" id="inlineZoomIn" class="btn btn-secondary btn-sm">+</button>
              <button type="button" id="inlineFitBtn" class="btn btn-secondary btn-sm">Fit</button>
              <button type="button" id="inlineOrigBtn" class="btn btn-secondary btn-sm">1:1</button>
              <button type="button" id="inlineFullscreenBtn" class="btn btn-primary btn-sm">Fullscreen</button>
            </div>
          </div>
          <div id="inlineStage" class="inline-image-stage">
            <img id="inlineImg" class="zoomable-img" src="${safeRawUrl}" alt="${safeName}" />
          </div>
        </div>
      `;

      const inlineStage = document.getElementById('inlineStage');
      const inlineImg = document.getElementById('inlineImg');
      const inlineZoomLabel = document.getElementById('inlineZoomLabel');
      const inlineResBadge = document.getElementById('inlineResBadge');
      const fullscreenBtn = document.getElementById('inlineFullscreenBtn');

      const inlineController = createPanZoomController({
        stage: inlineStage,
        img: inlineImg,
        zoomLabel: inlineZoomLabel
      });

      const initInlineImage = () => {
        inlineResBadge.textContent = `${inlineImg.naturalWidth} × ${inlineImg.naturalHeight}`;
        inlineController.fitToStage();
      };
      if (inlineImg.complete && inlineImg.naturalWidth) {
        initInlineImage();
      } else {
        inlineImg.addEventListener('load', initInlineImage);
      }

      document.getElementById('inlineZoomIn').addEventListener('click', () => inlineController.zoomIn());
      document.getElementById('inlineZoomOut').addEventListener('click', () => inlineController.zoomOut());
      document.getElementById('inlineFitBtn').addEventListener('click', () => inlineController.fitToStage());
      document
        .getElementById('inlineOrigBtn')
        .addEventListener('click', () => inlineController.setOriginalResolution());
      fullscreenBtn.addEventListener('click', () => openFullscreenViewer(file, true, fullscreenBtn));
    } else if (cat === 'video') {
      container.innerHTML = `<video controls preload="metadata" src="${safeRawUrl}"></video>`;
    } else if (cat === 'audio') {
      container.innerHTML = `<audio controls preload="metadata" src="${safeRawUrl}"></audio>`;
    } else if (cat === 'pdf') {
      container.innerHTML = `<iframe src="${safeRawUrl}" title="${safeName}"></iframe>`;
    } else if (cat === 'text' && file.size <= 2 * 1024 * 1024) {
      container.innerHTML = `<div class="preview-text">Loading...</div>`;
      try {
        const res = await fetch(file.rawUrl);
        const text = await res.text();
        const pre = container.querySelector('.preview-text');
        pre.textContent = text.slice(0, 100000);
      } catch {
        container.innerHTML = `<div class="preview-fallback">Preview unavailable</div>`;
      }
    } else {
      container.innerHTML = `<div class="preview-fallback">${safeName}</div>`;
    }
  }

  loadSharedFile();
})();
