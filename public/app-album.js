(function () {
  const albumMain = document.getElementById('albumMain');
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

  async function loadAlbum() {
    const parts = window.location.pathname.split('/').filter(Boolean);
    const short = parts[parts.length - 1];

    try {
      const res = await fetch(`/api/albums/${encodeURIComponent(short)}`);
      if (!res.ok) {
        showInlineError(`Album /c/${short} does not exist or has expired.`);
        albumMain.innerHTML = `
          <div class="card empty-card-panel">
            <h2 class="empty-card-title">Not Found</h2>
            <p class="empty-card-desc">
              /c/${escapeHtml(short)} does not exist.
            </p>
            <a href="/" class="btn btn-primary">Return</a>
          </div>
        `;
        return;
      }

      const album = await res.json();
      document.title = `${album.title} — sera.drop`;

      const totalBytes = album.files.reduce((sum, f) => sum + (f.size || 0), 0);

      const cardsHtml = album.files
        .map((f) => {
          const safeRawUrl = escapeHtml(f.rawUrl);
          const safeDownloadUrl = escapeHtml(f.downloadUrl);
          const safeDirectUrl = escapeHtml(f.directUrl || f.rawUrl);
          const safeName = escapeHtml(f.originalName);
          const safeCode = escapeHtml(f.code);
          let thumbHtml = '';
          if (f.previewCategory === 'image') {
            thumbHtml = `<img src="${safeRawUrl}" alt="${safeName}" class="album-thumb-img" loading="lazy" />`;
          } else if (f.previewCategory === 'video') {
            thumbHtml = `<video src="${safeRawUrl}" preload="metadata" muted class="album-thumb-img"></video>`;
          } else {
            thumbHtml = `<div class="album-thumb-placeholder">${escapeHtml((f.originalName.split('.').pop() || 'FILE').toUpperCase())}</div>`;
          }

          return `
            <div class="album-card">
              <a href="/s/${safeCode}" class="album-thumb-link">
                ${thumbHtml}
              </a>
              <div class="album-card-body">
                <a href="/s/${safeCode}" class="album-card-title" title="${safeName}">
                  ${safeName}
                </a>
                <div class="album-card-meta">
                  <span>${escapeHtml(formatBytes(f.size))}</span>
                  <span>${Number(f.downloads) || 0} dl</span>
                </div>
                <div class="album-card-actions">
                  <button type="button" class="btn btn-secondary btn-sm copy-direct" data-url="${safeDirectUrl}">Direct</button>
                  <a href="${safeDownloadUrl}" class="btn btn-primary btn-sm">Download</a>
                </div>
              </div>
            </div>
          `;
        })
        .join('');

      albumMain.innerHTML = `
        <div class="card album-header-card">
          <div class="album-header-row">
            <div>
              <span class="meta-pill pill-crimson">/c/${escapeHtml(album.short)}</span>
              <h1 class="album-main-title">${escapeHtml(album.title)}</h1>
              ${album.description ? `<p class="album-desc-text">${escapeHtml(album.description)}</p>` : ''}
              <div class="file-sub">
                <span>${album.files.length} files</span>
                <span>${escapeHtml(formatBytes(totalBytes))}</span>
              </div>
            </div>
            <div class="album-header-actions">
              <button type="button" id="copyAlbumUrlBtn" class="btn btn-primary btn-sm">Copy Link</button>
              <button type="button" id="reportAlbumBtn" class="btn btn-danger btn-sm">Report Abuse</button>
              <div class="qr-box qr-box-sm">
                <img id="albumQrImg" src="" alt="Album QR" class="qr-img-sm" />
              </div>
            </div>
          </div>
        </div>

        <div class="album-grid">
          ${cardsHtml}
        </div>
      `;

      const albumQrImg = document.getElementById('albumQrImg');
      if (window.SeraQR) {
        window.SeraQR.applyQrToElements(
          album.albumUrl || window.location.href,
          albumQrImg,
          null,
          `qr-album-${album.short}.png`
        );
      } else if (album.qrCodeDataUrl) {
        albumQrImg.src = album.qrCodeDataUrl;
      }

      document.getElementById('copyAlbumUrlBtn').addEventListener('click', () => {
        copyText(album.albumUrl, 'Album link');
      });

      const reportAlbumBtn = document.getElementById('reportAlbumBtn');
      if (reportAlbumBtn) {
        reportAlbumBtn.addEventListener('click', () => {
          reportModalCtrl.openReportModal(album.albumUrl || window.location.href, reportAlbumBtn);
        });
      }

      document.querySelectorAll('.copy-direct').forEach((btn) => {
        btn.addEventListener('click', () => copyText(btn.dataset.url, 'Direct link'));
        btn.addEventListener('auxclick', (e) => {
          if (e.button === 1) window.open(btn.dataset.url, '_blank', 'noopener,noreferrer');
        });
      });
    } catch (err) {
      showInlineError('Network error while loading album.');
      console.error(err);
    }
  }

  loadAlbum();
})();
