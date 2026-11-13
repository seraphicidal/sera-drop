(function () {
  function initUiFeedback() {
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

    return {
      showToast,
      showInlineError,
      clearInlineError,
      copyText
    };
  }

  function formatBytes(bytes) {
    if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.min(sizes.length - 1, Math.floor(Math.log(bytes) / Math.log(k)));
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

  function sanitizeUrl(url) {
    if (typeof url !== 'string') return '#';
    const trimmed = url.trim();
    if (trimmed.startsWith('/') && !trimmed.startsWith('//') && !trimmed.startsWith('/\\')) {
      return trimmed;
    }
    try {
      const parsed = new URL(trimmed, window.location.origin);
      if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
        return parsed.href;
      }
    } catch {}
    return '#';
  }

  window.SeraCommon = {
    initUiFeedback,
    formatBytes,
    escapeHtml,
    sanitizeUrl
  };
})();
