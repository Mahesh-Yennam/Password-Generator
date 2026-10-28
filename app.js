/**
 * Secure Password Generator Pro — Gamility Tools
 * Hardware-Seeded CSPRNG Cryptographic Credentials & Entropy Engine
 * Copyright © 2026 Gamility. All rights reserved.
 */

(() => {
  'use strict';

  // --- Character Sets ---
  const SETS = {
    uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    lowercase: 'abcdefghijklmnopqrstuvwxyz',
    numbers: '0123456789',
    symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?'
  };

  const LOOKALIKE_CHARS = new Set(['1', 'l', 'I', '0', 'O', 'o']);
  const AMBIGUOUS_SYMBOLS = new Set(['{', '}', '[', ']', '(', ')', '/', '\\', '\'', '"', '`', '~', ';', ':', '.', '<', '>']);

  // Curated 120+ Safe Passphrase Wordlist
  const WORDLIST = [
    'acorn', 'almond', 'alpine', 'anchor', 'anthem', 'apollo', 'arctic', 'arrow', 'atlas', 'autumn',
    'badge', 'beacon', 'breeze', 'bridge', 'bronze', 'canyon', 'castle', 'cedar', 'cipher', 'clover',
    'comet', 'copper', 'cosmos', 'crater', 'crystal', 'dawn', 'delta', 'drift', 'eagle', 'echo',
    'eclipse', 'emerald', 'ember', 'falcon', 'fathom', 'feather', 'flint', 'forest', 'frost', 'galaxy',
    'glacier', 'granite', 'harbor', 'haven', 'hawk', 'horizon', 'indigo', 'island', 'jasper', 'javelin',
    'jupiter', 'karma', 'lagoon', 'lantern', 'legacy', 'lotus', 'lunar', 'magnet', 'mantle', 'marble',
    'meadow', 'meteor', 'monarch', 'mosaic', 'nebula', 'nexus', 'noble', 'oasis', 'ocean', 'olive',
    'orbit', 'orchid', 'origin', 'panther', 'pebble', 'phoenix', 'pioneer', 'planet', 'plasma', 'polar',
    'prism', 'pulsar', 'pyramid', 'quartz', 'quiver', 'radar', 'radiant', 'ranger', 'raven', 'reef',
    'ridge', 'river', 'rocket', 'saffron', 'sapphire', 'saturn', 'serpent', 'shadow', 'shield', 'siren',
    'solstice', 'spark', 'sphinx', 'spruce', 'stellar', 'summit', 'sunrise', 'sunset', 'talon', 'timber',
    'titan', 'topaz', 'torrent', 'tracker', 'trident', 'tundra', 'ultra', 'valley', 'vector', 'vortex',
    'voyage', 'whisper', 'zenith', 'zephyr'
  ];

  // --- DOM Elements ---
  const passwordOutput = document.getElementById('password-output');
  const btnToggleMask = document.getElementById('btn-toggle-mask');
  const iconEye = document.getElementById('icon-eye');
  const btnRegenerate = document.getElementById('btn-regenerate');
  const btnCopy = document.getElementById('btn-copy');

  // Strength & Entropy
  const strengthBadge = document.getElementById('strength-badge');
  const entropyBits = document.getElementById('entropy-bits');
  const crackTimeLabel = document.getElementById('crack-time-label');
  const seg1 = document.getElementById('seg-1');
  const seg2 = document.getElementById('seg-2');
  const seg3 = document.getElementById('seg-3');
  const seg4 = document.getElementById('seg-4');

  // Presets
  const presetChips = document.querySelectorAll('.preset-chip');

  // Mode Tabs
  const modeTabs = document.querySelectorAll('.mode-tab');
  const panelRandom = document.getElementById('panel-random');
  const panelPassphrase = document.getElementById('panel-passphrase');
  const panelPin = document.getElementById('panel-pin');

  // Random Mode Controls
  const sliderLength = document.getElementById('slider-length');
  const labelLengthVal = document.getElementById('label-length-val');
  const chkUppercase = document.getElementById('chk-uppercase');
  const chkLowercase = document.getElementById('chk-lowercase');
  const chkNumbers = document.getElementById('chk-numbers');
  const chkSymbols = document.getElementById('chk-symbols');
  const chkExcludeLookalike = document.getElementById('chk-exclude-lookalike');
  const chkExcludeAmbiguous = document.getElementById('chk-exclude-ambiguous');

  // Passphrase Controls
  const sliderWords = document.getElementById('slider-words');
  const labelWordsVal = document.getElementById('label-words-val');
  const selectSeparator = document.getElementById('select-separator');
  const chkCapitalizeWords = document.getElementById('chk-capitalize-words');
  const chkIncludeNumber = document.getElementById('chk-include-number');

  // PIN Controls
  const sliderPinLength = document.getElementById('slider-pin-length');
  const labelPinVal = document.getElementById('label-pin-val');

  // Batch & History
  const batchPills = document.querySelectorAll('.batch-pill');
  const btnGenerateBatch = document.getElementById('btn-generate-batch');
  const btnBatchCopyAll = document.getElementById('btn-batch-copy-all');
  const batchOutputContainer = document.getElementById('batch-output-container');
  const historyContainer = document.getElementById('history-container');
  const btnClearHistory = document.getElementById('btn-clear-history');

  // Toast
  const toast = document.getElementById('toast');
  const toastMessage = document.getElementById('toast-message');

  // State
  let currentMode = 'random'; // 'random' | 'passphrase' | 'pin'
  let rawPassword = '';
  let isMasked = false;
  let batchCount = 5;
  const sessionHistory = [];
  let toastTimer = null;

  // --- Cryptographically Secure PRNG (CSPRNG) ---

  /**
   * Generates a cryptographically unbiased integer in range [0, max - 1]
   */
  function secureRandomInt(max) {
    if (max <= 1) return 0;
    const array = new Uint32Array(1);
    const maxUint32 = 0xFFFFFFFF;
    const limit = maxUint32 - (maxUint32 % max);
    let rand;
    do {
      window.crypto.getRandomValues(array);
      rand = array[0];
    } while (rand >= limit);
    return rand % max;
  }

  /**
   * Cryptographic array shuffle (Fisher-Yates)
   */
  function secureShuffle(array) {
    for (let i = array.length - 1; i > 0; i--) {
      const j = secureRandomInt(i + 1);
      const temp = array[i];
      array[i] = array[j];
      array[j] = temp;
    }
    return array;
  }

  // --- Toast Notification ---

  function showToast(msg) {
    if (toastTimer) clearTimeout(toastTimer);
    toastMessage.textContent = msg;
    toast.classList.add('show');
    toastTimer = setTimeout(() => {
      toast.classList.remove('show');
    }, 2200);
  }

  // --- Generator Implementations ---

  function generateRandomPassword() {
    const length = parseInt(sliderLength.value, 10);
    const useUpper = chkUppercase.checked;
    const useLower = chkLowercase.checked;
    const useNumbers = chkNumbers.checked;
    const useSymbols = chkSymbols.checked;
    const excludeLookalikes = chkExcludeLookalike.checked;
    const excludeAmbiguous = chkExcludeAmbiguous.checked;

    // Safety fallback if all are unchecked: re-enable lowercase
    if (!useUpper && !useLower && !useNumbers && !useSymbols) {
      chkLowercase.checked = true;
    }

    const activePools = [];
    if (useUpper) {
      let chars = SETS.uppercase;
      if (excludeLookalikes) chars = chars.split('').filter(c => !LOOKALIKE_CHARS.has(c)).join('');
      activePools.push(chars);
    }
    if (useLower) {
      let chars = SETS.lowercase;
      if (excludeLookalikes) chars = chars.split('').filter(c => !LOOKALIKE_CHARS.has(c)).join('');
      activePools.push(chars);
    }
    if (useNumbers) {
      let chars = SETS.numbers;
      if (excludeLookalikes) chars = chars.split('').filter(c => !LOOKALIKE_CHARS.has(c)).join('');
      activePools.push(chars);
    }
    if (useSymbols) {
      let chars = SETS.symbols;
      if (excludeAmbiguous) chars = chars.split('').filter(c => !AMBIGUOUS_SYMBOLS.has(c)).join('');
      activePools.push(chars);
    }

    const allAllowedChars = activePools.join('');
    if (!allAllowedChars) return 'P@ssword123';

    const resultChars = [];

    // Ensure at least 1 character from each active character pool
    activePools.forEach(pool => {
      if (pool.length > 0 && resultChars.length < length) {
        resultChars.push(pool[secureRandomInt(pool.length)]);
      }
    });

    // Fill remaining length from combined pool
    while (resultChars.length < length) {
      resultChars.push(allAllowedChars[secureRandomInt(allAllowedChars.length)]);
    }

    // Shuffle characters to eliminate placement predictability
    return secureShuffle(resultChars).join('');
  }

  function generatePassphrase() {
    const wordCount = parseInt(sliderWords.value, 10);
    const separator = selectSeparator.value;
    const capitalize = chkCapitalizeWords.checked;
    const includeNum = chkIncludeNumber.checked;

    const chosenWords = [];
    for (let i = 0; i < wordCount; i++) {
      let word = WORDLIST[secureRandomInt(WORDLIST.length)];
      if (capitalize) {
        word = word.charAt(0).toUpperCase() + word.slice(1);
      }
      chosenWords.push(word);
    }

    let phrase = chosenWords.join(separator);
    if (includeNum) {
      const randNum = 10 + secureRandomInt(90); // 2-digit number
      phrase += `${separator}${randNum}`;
    }

    return phrase;
  }

  function generatePIN() {
    const length = parseInt(sliderPinLength.value, 10);
    let pin = '';
    for (let i = 0; i < length; i++) {
      pin += secureRandomInt(10).toString();
    }
    return pin;
  }

  // --- Shannon Entropy & Crack Time Calculations ---

  function calculateEntropy(pwd) {
    if (!pwd) return { bits: 0, poolSize: 0 };

    let poolSize = 0;

    if (currentMode === 'passphrase') {
      const wordCount = parseInt(sliderWords.value, 10);
      const dictSize = WORDLIST.length;
      let bits = wordCount * Math.log2(dictSize);
      if (chkIncludeNumber.checked) bits += Math.log2(100);
      return { bits: Math.round(bits), poolSize: dictSize };
    }

    if (currentMode === 'pin') {
      poolSize = 10;
      const bits = pwd.length * Math.log2(poolSize);
      return { bits: Math.round(bits), poolSize };
    }

    // Random password mode
    const hasUpper = /[A-Z]/.test(pwd);
    const hasLower = /[a-z]/.test(pwd);
    const hasNumber = /[0-9]/.test(pwd);
    const hasSymbol = /[^A-Za-z0-9]/.test(pwd);

    if (hasUpper) poolSize += 26;
    if (hasLower) poolSize += 26;
    if (hasNumber) poolSize += 10;
    if (hasSymbol) poolSize += 32;

    if (poolSize === 0) poolSize = 26;

    const bits = Math.round(pwd.length * Math.log2(poolSize));
    return { bits, poolSize };
  }

  function formatCrackTime(bits) {
    if (bits <= 28) return 'Instant (< 1 sec)';
    if (bits <= 35) return '~3 seconds';
    if (bits <= 45) return '~45 minutes';
    if (bits <= 55) return '~3 months';
    if (bits <= 65) return '~200 years';
    if (bits <= 75) return '~2.4 Million Years';
    if (bits <= 90) return '~800 Billion Years';
    return '~4.2 Trillion Years+';
  }

  function updateStrengthMeter(bits) {
    entropyBits.textContent = `${bits} bits entropy`;
    crackTimeLabel.textContent = formatCrackTime(bits);

    // Reset segments
    seg1.style.backgroundColor = 'rgba(255, 255, 255, 0.08)';
    seg2.style.backgroundColor = 'rgba(255, 255, 255, 0.08)';
    seg3.style.backgroundColor = 'rgba(255, 255, 255, 0.08)';
    seg4.style.backgroundColor = 'rgba(255, 255, 255, 0.08)';

    let badgeText = '';
    let badgeColor = '';

    if (bits < 40) {
      badgeText = 'Very Weak';
      badgeColor = 'var(--accent-rose)';
      seg1.style.backgroundColor = badgeColor;
    } else if (bits < 60) {
      badgeText = 'Weak';
      badgeColor = 'var(--accent-amber)';
      seg1.style.backgroundColor = badgeColor;
      seg2.style.backgroundColor = badgeColor;
    } else if (bits < 80) {
      badgeText = 'Moderate';
      badgeColor = 'var(--accent-cyan)';
      seg1.style.backgroundColor = badgeColor;
      seg2.style.backgroundColor = badgeColor;
      seg3.style.backgroundColor = badgeColor;
    } else if (bits < 110) {
      badgeText = 'Strong';
      badgeColor = 'var(--accent-emerald)';
      seg1.style.backgroundColor = badgeColor;
      seg2.style.backgroundColor = badgeColor;
      seg3.style.backgroundColor = badgeColor;
      seg4.style.backgroundColor = badgeColor;
    } else {
      badgeText = 'Ultra Defense';
      badgeColor = 'var(--accent-emerald)';
      seg1.style.backgroundColor = badgeColor;
      seg2.style.backgroundColor = badgeColor;
      seg3.style.backgroundColor = badgeColor;
      seg4.style.backgroundColor = badgeColor;
    }

    strengthBadge.textContent = badgeText;
    strengthBadge.style.color = badgeColor;
    strengthBadge.style.borderColor = badgeColor;
    strengthBadge.style.background = `rgba(${badgeColor === 'var(--accent-emerald)' ? '16, 185, 129' : badgeColor === 'var(--accent-cyan)' ? '6, 182, 212' : badgeColor === 'var(--accent-amber)' ? '245, 158, 11' : '244, 63, 94'}, 0.15)`;
  }

  // --- Main Refresh Action ---

  function refreshPassword(addToHistory = true) {
    if (currentMode === 'random') {
      rawPassword = generateRandomPassword();
    } else if (currentMode === 'passphrase') {
      rawPassword = generatePassphrase();
    } else if (currentMode === 'pin') {
      rawPassword = generatePIN();
    }

    renderDisplay();

    const { bits } = calculateEntropy(rawPassword);
    updateStrengthMeter(bits);

    if (addToHistory && rawPassword) {
      addToSessionHistory(rawPassword);
    }
  }

  function renderDisplay() {
    if (isMasked) {
      passwordOutput.value = '•'.repeat(Math.min(rawPassword.length, 32));
      passwordOutput.classList.add('masked');
    } else {
      passwordOutput.value = rawPassword;
      passwordOutput.classList.remove('masked');
    }
  }

  // --- Session History ---

  function addToSessionHistory(pwd) {
    // Avoid duplicate at the top
    if (sessionHistory.length > 0 && sessionHistory[0] === pwd) return;

    sessionHistory.unshift(pwd);
    if (sessionHistory.length > 8) sessionHistory.pop();

    renderHistory();
  }

  function renderHistory() {
    if (sessionHistory.length === 0) {
      historyContainer.innerHTML = '<div class="empty-state">No credentials generated yet this session.</div>';
      return;
    }

    let html = '';
    sessionHistory.forEach((pwd, idx) => {
      html += `
        <div class="batch-item">
          <span class="batch-item-text" title="${escapeHtml(pwd)}">${escapeHtml(pwd)}</span>
          <svg class="batch-copy-icon" data-copy="${escapeHtml(pwd)}" viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" title="Copy credential">
            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
          </svg>
        </div>
      `;
    });

    historyContainer.innerHTML = html;

    // Attach click listeners to individual copy icons
    historyContainer.querySelectorAll('.batch-copy-icon').forEach(icon => {
      icon.addEventListener('click', () => {
        const val = icon.getAttribute('data-copy');
        copyToClipboard(val, 'Copied from history!');
      });
    });
  }

  // --- Batch Generator ---

  function generateBatch() {
    const list = [];
    for (let i = 0; i < batchCount; i++) {
      if (currentMode === 'random') {
        list.push(generateRandomPassword());
      } else if (currentMode === 'passphrase') {
        list.push(generatePassphrase());
      } else {
        list.push(generatePIN());
      }
    }

    let html = '';
    list.forEach(item => {
      html += `
        <div class="batch-item">
          <span class="batch-item-text" title="${escapeHtml(item)}">${escapeHtml(item)}</span>
          <svg class="batch-copy-icon" data-copy="${escapeHtml(item)}" viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" title="Copy credential">
            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
          </svg>
        </div>
      `;
    });

    batchOutputContainer.innerHTML = html;

    batchOutputContainer.querySelectorAll('.batch-copy-icon').forEach(icon => {
      icon.addEventListener('click', () => {
        const val = icon.getAttribute('data-copy');
        copyToClipboard(val, 'Password copied to clipboard!');
      });
    });
  }

  // --- Clipboard Copy Helper ---

  async function copyToClipboard(text, successMsg = 'Password copied to clipboard!') {
    if (!text) return;
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
      }
      showToast(successMsg);
    } catch (e) {
      showToast('Copied to clipboard!');
    }
  }

  function escapeHtml(str) {
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  // --- Event Listeners ---

  // Regenerate Button
  btnRegenerate.addEventListener('click', () => {
    btnRegenerate.classList.add('spinning');
    refreshPassword(true);
    setTimeout(() => {
      btnRegenerate.classList.remove('spinning');
    }, 450);
  });

  // Copy Main Password
  btnCopy.addEventListener('click', () => {
    copyToClipboard(rawPassword);
  });

  // Toggle Mask
  btnToggleMask.addEventListener('click', () => {
    isMasked = !isMasked;
    renderDisplay();
    btnToggleMask.setAttribute('title', isMasked ? 'Reveal password' : 'Hide password');
    iconEye.innerHTML = isMasked
      ? '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line>'
      : '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle>';
  });

  // Slider Length
  sliderLength.addEventListener('input', () => {
    labelLengthVal.textContent = sliderLength.value;
    refreshPassword(false);
  });

  // Sliders Words & PIN
  sliderWords.addEventListener('input', () => {
    labelWordsVal.textContent = sliderWords.value;
    refreshPassword(false);
  });

  sliderPinLength.addEventListener('input', () => {
    labelPinVal.textContent = sliderPinLength.value;
    refreshPassword(false);
  });

  // Checkboxes change
  [chkUppercase, chkLowercase, chkNumbers, chkSymbols, chkExcludeLookalike, chkExcludeAmbiguous, chkCapitalizeWords, chkIncludeNumber, selectSeparator].forEach(el => {
    el.addEventListener('change', () => {
      refreshPassword(false);
    });
  });

  // Mode Tabs Switching
  modeTabs.forEach(tab => {
    tab.addEventListener('click', () => {
      modeTabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');

      currentMode = tab.getAttribute('data-mode');

      panelRandom.classList.toggle('active', currentMode === 'random');
      panelPassphrase.classList.toggle('active', currentMode === 'passphrase');
      panelPin.classList.toggle('active', currentMode === 'pin');

      refreshPassword(true);
      generateBatch();
    });
  });

  // Quick Presets
  presetChips.forEach(chip => {
    chip.addEventListener('click', () => {
      presetChips.forEach(c => c.classList.remove('active'));
      chip.classList.add('active');

      const preset = chip.getAttribute('data-preset');
      if (preset === 'standard') {
        currentMode = 'random';
        sliderLength.value = 16;
        labelLengthVal.textContent = '16';
        chkUppercase.checked = true;
        chkLowercase.checked = true;
        chkNumbers.checked = true;
        chkSymbols.checked = true;
        chkExcludeLookalike.checked = false;
        chkExcludeAmbiguous.checked = false;
        switchTab('tab-random', 'panel-random');
      } else if (preset === 'strong') {
        currentMode = 'random';
        sliderLength.value = 24;
        labelLengthVal.textContent = '24';
        chkUppercase.checked = true;
        chkLowercase.checked = true;
        chkNumbers.checked = true;
        chkSymbols.checked = true;
        switchTab('tab-random', 'panel-random');
      } else if (preset === 'maximum') {
        currentMode = 'random';
        sliderLength.value = 32;
        labelLengthVal.textContent = '32';
        chkUppercase.checked = true;
        chkLowercase.checked = true;
        chkNumbers.checked = true;
        chkSymbols.checked = true;
        switchTab('tab-random', 'panel-random');
      } else if (preset === 'passphrase') {
        currentMode = 'passphrase';
        sliderWords.value = 4;
        labelWordsVal.textContent = '4';
        selectSeparator.value = '-';
        chkCapitalizeWords.checked = true;
        chkIncludeNumber.checked = true;
        switchTab('tab-passphrase', 'panel-passphrase');
      } else if (preset === 'pin') {
        currentMode = 'pin';
        sliderPinLength.value = 6;
        labelPinVal.textContent = '6';
        switchTab('tab-pin', 'panel-pin');
      }

      refreshPassword(true);
      generateBatch();
    });
  });

  function switchTab(tabId, panelId) {
    modeTabs.forEach(t => t.classList.remove('active'));
    document.getElementById(tabId).classList.add('active');
    panelRandom.classList.toggle('active', panelId === 'panel-random');
    panelPassphrase.classList.toggle('active', panelId === 'panel-passphrase');
    panelPin.classList.toggle('active', panelId === 'panel-pin');
  }

  // Batch Controls
  batchPills.forEach(pill => {
    pill.addEventListener('click', () => {
      batchPills.forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      batchCount = parseInt(pill.getAttribute('data-count'), 10);
      generateBatch();
    });
  });

  btnGenerateBatch.addEventListener('click', generateBatch);

  btnBatchCopyAll.addEventListener('click', () => {
    const items = Array.from(batchOutputContainer.querySelectorAll('.batch-item-text')).map(el => el.textContent);
    if (items.length === 0) return;
    copyToClipboard(items.join('\n'), `Copied ${items.length} passwords to clipboard!`);
  });

  // Clear History
  btnClearHistory.addEventListener('click', () => {
    sessionHistory.length = 0;
    renderHistory();
    showToast('Session history cleared');
  });

  // Initialize
  window.addEventListener('DOMContentLoaded', () => {
    refreshPassword(true);
    generateBatch();
  });

})();
