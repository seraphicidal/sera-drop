(function () {
  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('fileInput');
  const ttlSelect = document.getElementById('ttlSelect');
  const codeLengthSelect = document.getElementById('codeLengthSelect');
  const signedUrlToggle = document.getElementById('signedUrlToggle');
  const remoteUrlInput = document.getElementById('remoteUrlInput');
  const remoteUrlBtn = document.getElementById('remoteUrlBtn');
  const storageBadge = document.getElementById('storageBadge');

  const progressWrapper = document.getElementById('progressWrapper');
  const progressFileName = document.getElementById('progressFileName');
  const progressPercent = document.getElementById('progressPercent');
  const progressFill = document.getElementById('progressFill');

  const uploadQueueDrawer = document.getElementById('uploadQueueDrawer');
  const uploadQueueList = document.getElementById('uploadQueueList');
  const uploadQueueSummary = document.getElementById('uploadQueueSummary');
  const clearCompletedQueueBtn = document.getElementById('clearCompletedQueueBtn');

  const inlineError = document.getElementById('inlineError');
  const inlineErrorText = document.getElementById('inlineErrorText');
  const inlineErrorDismiss = document.getElementById('inlineErrorDismiss');

  const resultCard = document.getElementById('resultCard');
  const resultFileName = document.getElementById('resultFileName');
  const resultFileMeta = document.getElementById('resultFileMeta');
  const resultShortUrl = document.getElementById('resultShortUrl');
  const resultDirectUrl = document.getElementById('resultDirectUrl');
  const resultDedupeBadge = document.getElementById('resultDedupeBadge');
  const resultTtlBadge = document.getElementById('resultTtlBadge');
  const resultSignedBadge = document.getElementById('resultSignedBadge');
  const copyResultBtn = document.getElementById('copyResultBtn');
  const copyDirectBtn = document.getElementById('copyDirectBtn');
  const openSharePageBtn = document.getElementById('openSharePageBtn');
  const downloadQrBtn = document.getElementById('downloadQrBtn');
  const resultQrImage = document.getElementById('resultQrImage');
  const reportResultBtn = document.getElementById('reportResultBtn');

  const fileList = document.getElementById('fileList');
  const fileCountLabel = document.getElementById('fileCountLabel');
  const albumTitleInput = document.getElementById('albumTitleInput');
  const createAlbumBtn = document.getElementById('createAlbumBtn');
  const albumResultBanner = document.getElementById('albumResultBanner');
  const albumResultTitle = document.getElementById('albumResultTitle');
  const albumResultLink = document.getElementById('albumResultLink');
  const copyAlbumBtn = document.getElementById('copyAlbumBtn');
  const openAlbumBtn = document.getElementById('openAlbumBtn');
  const toast = document.getElementById('toast');

  let currentLoadedFiles = [];
  const selectedForAlbum = new Set();
  let statusPollAttempts = 0;
  let currentAlbumUrl = '';

  const queueItems = [];
  let queueSeq = 0;
  let isProcessingQueue = false;

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
    if (!bytes || bytes <= 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.min(sizes.length - 1, Math.floor(Math.log(bytes) / Math.log(k)));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  function formatSpeed(bytesPerSec) {
    if (!bytesPerSec || !Number.isFinite(bytesPerSec) || bytesPerSec <= 0) return '';
    if (bytesPerSec >= 1024 * 1024) {
      return (bytesPerSec / (1024 * 1024)).toFixed(1) + ' MB/s';
    }
    return Math.max(1, Math.round(bytesPerSec / 1024)) + ' KB/s';
  }

  function formatEta(seconds) {
    if (seconds === undefined || !Number.isFinite(seconds) || seconds < 0) return '';
    if (seconds < 1) return '<1s';
    if (seconds < 60) return Math.ceil(seconds) + 's';
    const mins = Math.floor(seconds / 60);
    const secs = Math.ceil(seconds % 60);
    return mins + 'm ' + secs + 's';
  }

  function formatDate(iso) {
    const d = new Date(iso);
    return d.toLocaleString(undefined, {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  }

  function formatRemainingTtl(expiresAt) {
    if (!expiresAt) return null;
    const diffMs = new Date(expiresAt).getTime() - Date.now();
    if (diffMs <= 0) return 'Expired';
    const mins = Math.ceil(diffMs / 60000);
    if (mins < 60) return `${mins}m`;
    const hrs = (diffMs / 3600000).toFixed(1);
    return `${hrs}h`;
  }

  function getExtBadge(filename) {
    const parts = (filename || '').split('.');
    if (parts.length > 1) {
      return parts.pop().slice(0, 4).toUpperCase();
    }
    return 'FILE';
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  const OWNED_STORAGE_KEY = 'sera_drop_owned_files';

  function getOwnedFilesMap() {
    try {
      return JSON.parse(localStorage.getItem(OWNED_STORAGE_KEY) || '{}');
    } catch {
      return {};
    }
  }

  function saveOwnedFileToken(code, deleteToken) {
    if (!code || !deleteToken) return;
    const map = getOwnedFilesMap();
    map[code] = deleteToken;
    localStorage.setItem(OWNED_STORAGE_KEY, JSON.stringify(map));
  }

  function removeOwnedFileToken(code) {
    const map = getOwnedFilesMap();
    delete map[code];
    localStorage.setItem(OWNED_STORAGE_KEY, JSON.stringify(map));
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

  function bindCatboxClickBehavior(el, getUrl, label) {
    if (!el) return;
    el.addEventListener('click', () => copyText(getUrl(), label));
    el.addEventListener('auxclick', (e) => {
      if (e.button === 1) {
        e.preventDefault();
        window.open(getUrl(), '_blank', 'noopener,noreferrer');
      }
    });
  }

  bindCatboxClickBehavior(resultShortUrl, () => resultShortUrl.value, 'Share link');
  bindCatboxClickBehavior(resultDirectUrl, () => resultDirectUrl.value, 'Direct link');

  if (copyAlbumBtn) {
    copyAlbumBtn.addEventListener('click', () => {
      if (currentAlbumUrl) copyText(currentAlbumUrl, 'Album link');
    });
  }

  if (reportResultBtn) {
    reportResultBtn.addEventListener('click', () => {
      reportModalCtrl.openReportModal(resultShortUrl.value || window.location.href, reportResultBtn);
    });
  }

  function renderQueueDrawer() {
    if (!uploadQueueDrawer || !uploadQueueList) return;
    if (queueItems.length === 0) {
      uploadQueueDrawer.classList.remove('active');
      uploadQueueList.innerHTML = '';
      return;
    }

    uploadQueueDrawer.classList.add('active');
    const doneCount = queueItems.filter((item) => item.status === 'Done').length;
    if (uploadQueueSummary) {
      uploadQueueSummary.textContent = `${doneCount} / ${queueItems.length} completed`;
    }

    uploadQueueList.innerHTML = '';
    queueItems.forEach((entry) => {
      const row = document.createElement('div');
      row.className = 'queue-item';
      row.setAttribute('data-queue-status', entry.status.toLowerCase());

      const statusBadgeClass =
        entry.status === 'Done'
          ? 'queue-status-done'
          : entry.status === 'Failed' || entry.status === 'Cancelled'
            ? 'queue-status-failed'
            : entry.status === 'Uploading'
              ? 'queue-status-uploading'
              : 'queue-status-queued';

      const telemetryParts = [formatBytes(entry.file.size)];
      if (entry.status === 'Uploading') {
        if (entry.speedText) telemetryParts.push(entry.speedText);
        if (entry.etaText) telemetryParts.push(`ETA ${entry.etaText}`);
      } else if (entry.errorMessage) {
        telemetryParts.push(entry.errorMessage);
      }

      row.innerHTML = `
        <div class="queue-item-header">
          <div class="queue-item-title">
            <span class="queue-item-name" title="${escapeHtml(entry.file.name)}">${escapeHtml(entry.file.name)}</span>
            <span class="queue-item-meta">${escapeHtml(telemetryParts.join(' · '))}</span>
          </div>
          <div class="queue-item-actions">
            <span class="queue-status-pill ${statusBadgeClass}">${escapeHtml(entry.status)}</span>
            ${
              entry.status === 'Uploading' || entry.status === 'Queued'
                ? '<button type="button" class="btn btn-danger btn-sm queue-cancel-btn">Cancel</button>'
                : ''
            }
            ${
              entry.status === 'Failed' || entry.status === 'Cancelled'
                ? '<button type="button" class="btn btn-secondary btn-sm queue-retry-btn">Retry</button>'
                : ''
            }
          </div>
        </div>
        <div class="progress-track">
          <div class="progress-fill" style="width: ${Math.max(0, Math.min(100, entry.percent))}%;"></div>
        </div>
      `;

      const cancelBtn = row.querySelector('.queue-cancel-btn');
      if (cancelBtn) {
        cancelBtn.addEventListener('click', () => cancelQueueItem(entry.id));
      }
      const retryBtn = row.querySelector('.queue-retry-btn');
      if (retryBtn) {
        retryBtn.addEventListener('click', () => retryQueueItem(entry.id));
      }

      uploadQueueList.appendChild(row);
    });
  }

  function cancelQueueItem(id) {
    const entry = queueItems.find((item) => item.id === id);
    if (!entry) return;
    if (entry.status === 'Uploading' && entry.xhr) {
      entry.status = 'Cancelled';
      entry.xhr.abort();
      entry.xhr = null;
      renderQueueDrawer();
      return;
    }
    if (entry.status === 'Queued') {
      entry.status = 'Cancelled';
      renderQueueDrawer();
    }
  }

  function retryQueueItem(id) {
    const entry = queueItems.find((item) => item.id === id);
    if (!entry) return;
    if (entry.status !== 'Failed' && entry.status !== 'Cancelled') return;
    entry.status = 'Queued';
    entry.percent = 0;
    entry.speedText = '';
    entry.etaText = '';
    entry.errorMessage = '';
    clearInlineError();
    renderQueueDrawer();
    void processQueue();
  }

  if (clearCompletedQueueBtn) {
    clearCompletedQueueBtn.addEventListener('click', () => {
      for (let i = queueItems.length - 1; i >= 0; i--) {
        if (
          queueItems[i].status === 'Done' ||
          queueItems[i].status === 'Cancelled' ||
          queueItems[i].status === 'Failed'
        ) {
          queueItems.splice(i, 1);
        }
      }
      renderQueueDrawer();
    });
  }

  function enqueueFiles(files) {
    if (!files || !files.length) return;
    clearInlineError();
    for (const file of files) {
      queueItems.push({
        id: ++queueSeq,
        file,
        status: 'Queued',
        percent: 0,
        speedText: '',
        etaText: '',
        errorMessage: '',
        xhr: null
      });
    }
    renderQueueDrawer();
    void processQueue();
  }

  async function processQueue() {
    if (isProcessingQueue) return;
    isProcessingQueue = true;
    try {
      while (true) {
        const nextEntry = queueItems.find((item) => item.status === 'Queued');
        if (!nextEntry) break;
        await runQueueUpload(nextEntry);
      }
    } finally {
      isProcessingQueue = false;
    }
  }

  function runQueueUpload(entry) {
    return new Promise((resolve) => {
      const file = entry.file;
      const formData = new FormData();
      formData.append('ttl', ttlSelect.value);
      formData.append('codeLength', codeLengthSelect.value);
      formData.append('requireSignedUrl', String(signedUrlToggle.checked));
      formData.append('file', file);

      entry.status = 'Uploading';
      entry.percent = 0;
      entry.speedText = '';
      entry.etaText = '';
      entry.errorMessage = '';
      renderQueueDrawer();

      progressFileName.textContent = file.name;
      progressPercent.textContent = '0%';
      progressFill.style.width = '0%';
      progressWrapper.classList.add('active');

      const startedAt = performance.now();
      const xhr = new XMLHttpRequest();
      entry.xhr = xhr;
      xhr.open('POST', '/api/upload', true);
      xhr.setRequestHeader('X-Requested-With', 'sera.drop');

      xhr.upload.onprogress = (e) => {
        if (e.lengthComputable) {
          const pct = Math.round((e.loaded / e.total) * 100);
          const elapsedSec = Math.max(0.05, (performance.now() - startedAt) / 1000);
          const speedBps = e.loaded / elapsedSec;
          const remainingBytes = Math.max(0, e.total - e.loaded);
          const etaSec = speedBps > 0 ? remainingBytes / speedBps : undefined;

          entry.percent = pct;
          entry.speedText = formatSpeed(speedBps);
          entry.etaText = formatEta(etaSec);
          progressPercent.textContent = `${pct}%`;
          progressFill.style.width = `${pct}%`;
          renderQueueDrawer();
        }
      };

      xhr.onload = () => {
        entry.xhr = null;
        progressWrapper.classList.remove('active');
        if (xhr.status >= 200 && xhr.status < 300) {
          entry.status = 'Done';
          entry.percent = 100;
          entry.speedText = '';
          entry.etaText = '';
          renderQueueDrawer();

          const data = JSON.parse(xhr.responseText);
          if (data.deleteToken) {
            saveOwnedFileToken(data.code, data.deleteToken);
          }
          displayResult(data);
          loadFiles();
          checkPublicStatus();
          showToast(data.deduplicated ? 'Deduplicated' : 'Uploaded');
        } else {
          let errMsg = 'Upload failed';
          try {
            errMsg = JSON.parse(xhr.responseText).error || errMsg;
          } catch {}
          entry.status = 'Failed';
          entry.errorMessage = errMsg;
          renderQueueDrawer();
          showToast(errMsg);
          showInlineError(`${file.name}: ${errMsg}`);
        }
        resolve();
      };

      xhr.onerror = () => {
        entry.xhr = null;
        progressWrapper.classList.remove('active');
        entry.status = 'Failed';
        entry.errorMessage = 'Network error';
        renderQueueDrawer();
        showToast('Network error');
        showInlineError(`${file.name}: Network error during upload.`);
        resolve();
      };

      xhr.onabort = () => {
        entry.xhr = null;
        progressWrapper.classList.remove('active');
        entry.status = 'Cancelled';
        entry.speedText = '';
        entry.etaText = '';
        renderQueueDrawer();
        showToast('Upload cancelled');
        resolve();
      };

      xhr.send(formData);
    });
  }

  dropzone.addEventListener('click', (e) => {
    if (e.target !== fileInput) {
      fileInput.click();
    }
  });

  dropzone.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      fileInput.click();
    }
  });

  fileInput.addEventListener('change', () => {
    const files = Array.from(fileInput.files || []);
    fileInput.value = '';
    enqueueFiles(files);
  });

  ['dragenter', 'dragover'].forEach((evt) => {
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.add('drag-over');
    });
  });

  ['dragleave', 'drop'].forEach((evt) => {
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.remove('drag-over');
    });
  });

  dropzone.addEventListener('drop', (e) => {
    const files = Array.from(e.dataTransfer?.files || []);
    enqueueFiles(files);
  });

  window.addEventListener('paste', (e) => {
    if (document.activeElement === remoteUrlInput || document.activeElement === albumTitleInput) {
      return;
    }
    const items = Array.from(e.clipboardData?.files || []);
    enqueueFiles(items);
  });

  async function uploadRemoteUrl() {
    const url = remoteUrlInput.value.trim();
    if (!url) {
      showToast('Enter a valid URL');
      showInlineError('Please enter a valid HTTP or HTTPS URL to fetch.');
      return;
    }
    clearInlineError();
    remoteUrlBtn.disabled = true;
    remoteUrlBtn.textContent = '...';
    try {
      const res = await fetch('/api/url-upload', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'sera.drop'
        },
        body: JSON.stringify({
          url,
          ttl: ttlSelect.value,
          codeLength: codeLengthSelect.value,
          requireSignedUrl: signedUrlToggle.checked
        })
      });
      const data = await res.json();
      if (!res.ok) {
        const msg = data.error || 'Fetch failed';
        showToast(msg);
        showInlineError(msg);
        return;
      }
      remoteUrlInput.value = '';
      if (data.deleteToken) {
        saveOwnedFileToken(data.code, data.deleteToken);
      }
      displayResult(data);
      loadFiles();
      checkPublicStatus();
      showToast('Uploaded');
    } catch {
      showToast('Network error');
      showInlineError('Network error while fetching remote URL.');
    } finally {
      remoteUrlBtn.disabled = false;
      remoteUrlBtn.textContent = 'Fetch';
    }
  }

  remoteUrlBtn.addEventListener('click', uploadRemoteUrl);
  remoteUrlInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      uploadRemoteUrl();
    }
  });

  function displayResult(item) {
    resultFileName.textContent = item.originalName;
    const metaParts = [
      `<span>${escapeHtml(formatBytes(item.size))}</span>`,
      `<span>${escapeHtml(item.code)}</span>`
    ];
    if (item.sha256) {
      metaParts.push(`<span>${escapeHtml(item.sha256.slice(0, 12))}</span>`);
    }
    resultFileMeta.innerHTML = metaParts.join('');
    resultShortUrl.value = item.shortUrl;
    resultDirectUrl.value = item.directUrl || item.rawUrl;
    openSharePageBtn.href = `/s/${encodeURIComponent(item.code)}`;

    if (window.SeraQR) {
      window.SeraQR.applyQrToElements(
        item.shortUrl || window.location.origin + `/s/${item.code}`,
        resultQrImage,
        downloadQrBtn,
        `qr-${item.code}.png`
      );
    } else if (item.qrCodeDataUrl) {
      resultQrImage.src = item.qrCodeDataUrl;
      downloadQrBtn.href = item.qrCodeDataUrl;
      downloadQrBtn.download = `qr-${item.code}.png`;
    }

    resultDedupeBadge.classList.toggle('hidden-el', !item.deduplicated);
    if (item.expiresAt) {
      resultTtlBadge.classList.remove('hidden-el');
      resultTtlBadge.textContent = `${formatRemainingTtl(item.expiresAt)}`;
    } else {
      resultTtlBadge.classList.add('hidden-el');
    }
    resultSignedBadge.classList.toggle('hidden-el', !item.requireSignedUrl);

    resultCard.classList.add('active');
  }

  copyResultBtn.addEventListener('click', () => copyText(resultShortUrl.value, 'Share link'));
  copyDirectBtn.addEventListener('click', () => copyText(resultDirectUrl.value, 'Direct link'));

  async function createAlbum() {
    const codesToInclude =
      selectedForAlbum.size > 0
        ? Array.from(selectedForAlbum)
        : currentLoadedFiles.map((f) => f.code);

    if (!codesToInclude.length) {
      showToast('Select at least one file');
      showInlineError('Upload or select at least one file to create an album.');
      return;
    }

    clearInlineError();
    const title = albumTitleInput.value.trim() || `Album (${codesToInclude.length})`;
    createAlbumBtn.disabled = true;
    try {
      const res = await fetch('/api/albums', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'sera.drop'
        },
        body: JSON.stringify({
          title,
          description: `${codesToInclude.length} files`,
          files: codesToInclude
        })
      });
      const data = await res.json();
      if (!res.ok) {
        const msg = data.error || 'Failed to create album';
        showToast(msg);
        showInlineError(msg);
        return;
      }
      albumTitleInput.value = '';
      selectedForAlbum.clear();
      currentAlbumUrl = data.albumUrl;
      albumResultTitle.textContent = `${data.title} (${data.files.length})`;
      albumResultLink.textContent = data.albumUrl;
      albumResultLink.href = `/c/${encodeURIComponent(data.short)}`;
      openAlbumBtn.href = `/c/${encodeURIComponent(data.short)}`;
      albumResultBanner.classList.remove('hidden-el');
      copyText(data.albumUrl, 'Album link');
      loadFiles();
    } catch {
      showToast('Error creating album');
      showInlineError('Network error while creating album.');
    } finally {
      createAlbumBtn.disabled = false;
    }
  }

  createAlbumBtn.addEventListener('click', createAlbum);

  async function deleteFile(code) {
    const owned = getOwnedFilesMap();
    const token = owned[code] || '';
    const headers = { 'X-Requested-With': 'sera.drop' };
    if (token) {
      headers['X-Delete-Token'] = token;
    }
    const res = await fetch(`/api/files/${encodeURIComponent(code)}`, {
      method: 'DELETE',
      headers
    });
    if (res.ok) {
      removeOwnedFileToken(code);
      selectedForAlbum.delete(code);
      showToast('Deleted');
      loadFiles();
      checkPublicStatus();
    } else {
      showToast('Unauthorized');
      showInlineError('Could not delete file: missing or invalid ownership token.');
    }
  }

  async function loadFiles() {
    try {
      const ownedCodes = Object.keys(getOwnedFilesMap());
      const query = ownedCodes.length ? `?codes=${encodeURIComponent(ownedCodes.join(','))}` : '';
      const res = await fetch(`/api/files${query}`);
      const files = await res.json();
      currentLoadedFiles = Array.isArray(files) ? files : [];
      fileCountLabel.textContent = `${currentLoadedFiles.length}`;

      if (currentLoadedFiles.length === 0) {
        fileList.innerHTML = `<div class="card empty-state">No files</div>`;
        return;
      }

      fileList.innerHTML = '';
      const execExts = new Set(['EXE', 'BAT', 'PS1', 'CMD', 'VBS', 'MSI', 'SCR', 'COM', 'LNK']);
      currentLoadedFiles.forEach((f) => {
        const safeName = escapeHtml(f.originalName);
        const rawBadge = getExtBadge(f.originalName);
        const safeBadge = escapeHtml(rawBadge);
        const safeCode = escapeHtml(f.code);
        const isExec = execExts.has(rawBadge);
        const warnTag = isExec ? `<span class="tag-warn">Executable</span>` : '';
        const dedupeTag = f.deduplicated ? `<span class="tag-mono">Dedupe</span>` : '';
        const ttlRemaining = formatRemainingTtl(f.expiresAt);
        const ttlTag = ttlRemaining ? `<span class="tag-accent">${escapeHtml(ttlRemaining)}</span>` : '';
        const signedTag = f.requireSignedUrl ? `<span class="tag-accent">Signed</span>` : '';
        const checkedAttr = selectedForAlbum.has(f.code) ? 'checked' : '';

        const row = document.createElement('div');
        row.className = 'file-item';
        row.innerHTML = `
          <div class="file-meta">
            <input type="checkbox" class="album-check" data-code="${safeCode}" ${checkedAttr} aria-label="Select ${safeName} for Album" />
            <div class="file-type-badge">${safeBadge}</div>
            <div class="file-info">
              <div class="file-name" title="${safeName}">${safeName}</div>
              <div class="file-sub">
                ${warnTag}
                ${dedupeTag}
                ${ttlTag}
                ${signedTag}
                <span>${escapeHtml(formatBytes(f.size))}</span>
                <span>${Number(f.downloads) || 0} dl</span>
                <span>${escapeHtml(formatDate(f.createdAt))}</span>
                <a href="/s/${safeCode}" class="file-code-link">/s/${safeCode}</a>
              </div>
            </div>
          </div>
          <div class="file-actions">
            <button type="button" class="btn btn-secondary btn-sm copy-btn">Copy</button>
            <button type="button" class="btn btn-secondary btn-sm copy-direct-btn">Direct</button>
            <a href="/s/${safeCode}" class="btn btn-secondary btn-sm">Preview</a>
            <button type="button" class="btn btn-secondary btn-sm report-file-btn">Report</button>
            <button type="button" class="btn btn-danger btn-sm delete-btn">Delete</button>
          </div>
        `;

        const checkEl = row.querySelector('.album-check');
        checkEl.addEventListener('change', () => {
          if (checkEl.checked) {
            selectedForAlbum.add(f.code);
          } else {
            selectedForAlbum.delete(f.code);
          }
        });

        bindCatboxClickBehavior(row.querySelector('.copy-btn'), () => f.shortUrl, 'Share link');
        bindCatboxClickBehavior(
          row.querySelector('.copy-direct-btn'),
          () => f.directUrl || f.rawUrl,
          'Direct link'
        );
        const reportBtn = row.querySelector('.report-file-btn');
        if (reportBtn) {
          reportBtn.addEventListener('click', () => {
            reportModalCtrl.openReportModal(
              f.shortUrl || window.location.origin + `/s/${f.code}`,
              reportBtn
            );
          });
        }
        row.querySelector('.delete-btn').addEventListener('click', () => deleteFile(f.code));
        fileList.appendChild(row);
      });
    } catch (err) {
      console.error('Error loading files:', err);
    }
  }

  async function checkPublicStatus() {
    try {
      const res = await fetch('/api/status');
      const data = await res.json();
      const badge = document.getElementById('publicUrlBadge');
      if (typeof data.storageUsedBytes === 'number') {
        storageBadge.innerHTML = `<span>${escapeHtml(formatBytes(data.storageUsedBytes))} / 5 GB</span><span>Max 500 MB/file</span>`;
      }
      const isLocalHost =
        window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
      if (data.publicUrl && isLocalHost && badge) {
        badge.href = data.publicUrl;
        badge.textContent = data.publicUrl.replace(/^https?:\/\//, '');
        badge.classList.remove('hidden-el');
      } else if (!data.publicUrl && data.tunnelEnabled && statusPollAttempts < 15) {
        statusPollAttempts += 1;
        setTimeout(checkPublicStatus, 2000);
      }
    } catch {}
  }

  loadFiles();
  checkPublicStatus();
})();
