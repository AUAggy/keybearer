/**
 * kbpage-v2.js - Simplified UI controller for Keybearer v2
 *
 * Changes from v1:
 * - Removed all entropy collection code (crypto.getRandomValues() is always ready)
 * - Simplified Web Worker initialization (no more Blob worker)
 * - Cleaner initialization flow
 */

kbp = {
  // Track ready state
  _ready_wordlist: false,
  _ready_ngram: false,
  kb: null, // WebWorker

  /**
   * Initialize Keybearer
   */
  init: function(wordlistURL, badngramlistURL) {
    try {
      new Blob();
    } catch (err) {
      $('#error').append([
        '<div class="alert alert-error">',
        '<h3>This browser does not support the FileAPI,',
        'which is required.',
        'Consider trying again with the latest Firefox or Chrome.',
        '</h3></div>'
      ].join('\n'));
      return;
    }

    // Load wordlists
    keybearer.loadWordlist(wordlistURL, '_wordlist', function() {
      kbp._ready_wordlist = true;
      kbp.try_start();
    });
    keybearer.loadWordlist(badngramlistURL, '_badngramlist', function() {
      kbp._ready_ngram = true;
      kbp.try_start();
    });
  },

  /**
   * Start app when ready (no entropy waiting needed!)
   */
  try_start: function() {
    if (kbp._ready_wordlist && kbp._ready_ngram) {
      kbp.setupWorker();
      kbp.bind_input();
    }
  },

  /**
   * Set up Web Worker for encryption
   */
  setupWorker: function() {
    // Use the bundled worker file
    kbp.kb = new Worker('../../dist/kb-worker.js');

    kbp.kb.onmessage = function(e) {
      const handler = e.data.f;
      const result = e.data.r;

      switch (handler) {
        case 'setPlaintext':
          $('#encrypt').attr('class', 'btn').click(kbp.encrypt);
          break;
        case 'encryptWithPasswords':
          if (e.data.c) {
            // Progress update
            $('#ksprogressbar').width(e.data.c * 100 + '%');
            $('#ksprogressbar').html(kbp.toPercent(e.data.c));
          } else if (e.data.r) {
            // Encryption complete
            $('#encprogress').delay(1000).fadeOut(400);
            const blob = new Blob([e.data.r], { type: 'application/json' });
            const link = document.createElement('a');
            link.href = window.URL.createObjectURL(blob);
            link.download = keybearer.getFileName() + '.kbr.json';
            link.innerHTML = 'Download encrypted ' + link.download;
            window.URL.revokeObjectURL($('#encdownloadlink > a').attr('href'));
            $('#encdownloadlink').empty().append(link);
          }
          break;
      }
    };

    // Initialize salt in worker
    kbp.kb.postMessage({ f: 'makeSalt' });
  },

  /**
   * Bind input change events
   */
  bind_input: function() {
    $('#num_pass > .btn').click(kbp.generateAllFriendPass);
    $('#num_pass > .btn').click(kbp.checkUnlockPass);
    $('#num_pass > .btn').click(kbp.updateKeygenCount);
    $('#pbkdf2iterations > .btn').click(kbp.updatePBKDF2Iterations);
    $('#num_unlock_pass > .btn').click(kbp.updateKeygenCount);
    $('#pass_len > .btn').click(kbp.generateAllFriendPass);
    $('#secretfile').change(kbp.choosePlaintextFile);
    $('#decfile').change(kbp.chooseEncryptedFile);
    $('#num_pass > .active').click();
    $('#pbkdf2iterations > .active').click();
    $('#copypass').click(kbp.copyPasswords);
  },

  /**
   * Generate password fields for all friends
   */
  generateAllFriendPass: function(evt) {
    const gk = $('#generated_pass');
    gk.empty();
    let n_keys, p_len;

    if (evt.target.id.match(/l/)) {
      p_len = evt.target.value;
      n_keys = kbp.getNumPass();
    } else {
      n_keys = evt.target.value;
      p_len = $('#pass_len > .active').val();
    }

    const reset = function(ev) {
      const s = '#' + ev.currentTarget.id.replace('reset_', '');
      $(s).val(keybearer.makePassword(p_len));
      keybearer.resetKeys();
    };

    for (let i = 0; i < n_keys; i++) {
      gk.append(kbp.mkFriendPass(i, keybearer.makePassword(p_len)));
      $('#reset_pass' + i).click(reset);
    }
  },

  /**
   * Generate password entry fields for decryption
   */
  generateAllDecPass: function(n, m) {
    const da = $('#decpass_area');
    da.empty();
    da.append([
      '<div class="alert alert-info">',
      'Enter up to',
      n,
      'passcodes, including spaces. Only',
      m,
      'passcodes are necessary.',
      '</div>'
    ].join(' '));
    for (let i = 0; i < n; i++) {
      da.append(kbp.mkDecPass(i));
    }
  },

  /**
   * Ensure unlock count doesn't exceed total passwords
   */
  checkUnlockPass: function(evt) {
    const max_sel = evt.target.value;
    const sel = Math.min(max_sel, kbp.getNumUnlock());
    const nuk = $('#num_unlock_pass');
    nuk.empty();

    for (let i = 1; i <= max_sel; i++) {
      nuk.append(
        '<button id="mI" class="btn" value=I>I</button>'.replace(
          'btn',
          'btn' + (i == sel ? ' active' : '')
        ).replace(/I/g, i)
      );
    }
    $('#num_unlock_pass > .btn').click(kbp.updateKeygenCount);
  },

  getNumPass: function() {
    return $('#num_pass > .active').val();
  },

  getNumUnlock: function() {
    return $('#num_unlock_pass > .active').val();
  },

  getAllPass: function() {
    const npass = kbp.getNumPass();
    const passwords = [];
    for (let i = 0; i < npass; i++) {
      passwords[i] = keybearer.normalizeString($('#pass' + i).val());
    }
    return passwords;
  },

  /**
   * Get M passwords from decryption form
   */
  getMDecPass: function(n, m) {
    let passwords = [];
    for (let i = 0; i < n; i++) {
      $('#label' + i).attr('class', 'add-on');
      const s = keybearer.normalizeString($('#decpass' + i).val());
      if (s.length > 0) passwords.push(s);
    }

    if (passwords.length < m) {
      alert('You must enter at least ' + m + ' passcodes to decrypt this message.');
      return passwords;
    }

    keybearer.shuffle(passwords);
    passwords = passwords.slice(0, m);
    passwords.sort();

    // Highlight winning keys
    for (let i = 0; i < n; i++) {
      const str = keybearer.normalizeString($('#decpass' + i).val());
      for (let j = 0; j < m; j++) {
        if (str == passwords[j]) {
          $('#label' + i).addClass('btn-info');
        }
      }
    }
    return passwords;
  },

  /**
   * Encrypt file with passwords
   */
  encrypt: function() {
    if (!keybearer.isPlaintextReady()) {
      alert('You must load a file before encrypting it!');
      return;
    }

    const passwords = kbp.getAllPass();
    for (let i = 0; i < passwords.length; i++) {
      if (passwords[i].length === 0) {
        alert('Passwords cannot be blank (or only whitespace)');
        return;
      }
    }

    $('#encprogress').animate({ opacity: 1, display: 'toggle' });
    kbp.kb.postMessage({
      f: 'encryptWithPasswords',
      p: [passwords, kbp.getNumUnlock()],
      c: true
    });
  },

  /**
   * Update key generation count display
   */
  updateKeygenCount: function(evt) {
    let n, m;
    if (evt.target.id.match(/n/)) {
      n = evt.target.value;
      m = kbp.getNumUnlock();
    } else {
      n = kbp.getNumPass();
      m = evt.target.value;
    }
    $('#nkeys_to_gen').text(kbp.nChooseK(n, m));
  },

  /**
   * Update PBKDF2 iterations
   */
  updatePBKDF2Iterations: function(evt) {
    kbp.kb.postMessage({ f: 'setPBKDF2Iterations', p: [evt.target.value] });
  },

  // Friend password form template
  ffTemplate: [
    '<form class="pass form-inline input-prepend input-append">',
    '<input id="reset_passX" class="btn" type="button" value="Regenerate"></input>',
    '<input type="text" class="password regen" id="passX" value="PASSWORD" />',
    '<span class="add-on">X+1</span>',
    '</form>'
  ].join('\n'),

  // Decryption entry template
  decTemplate: [
    '<form class="decpass pass form-inline input-prepend">',
    '<span id="labelX" class="add-on">X+1</span>',
    '<input type="text" class="decpassinput decpassin" id="decpassX" value="" />',
    '</form>'
  ].join('\n'),

  /**
   * Fill in friend password template
   */
  mkFriendPass: function(friendID, password) {
    return kbp.ffTemplate
      .replace(/X\+1/g, friendID + 1)
      .replace(/X/g, friendID)
      .replace('PASSWORD', password);
  },

  /**
   * Fill in decryption entry template
   */
  mkDecPass: function(friendID) {
    return kbp.decTemplate
      .replace(/X\+1/g, friendID + 1)
      .replace(/X/g, friendID);
  },

  /**
   * Calculate n choose k
   */
  nChooseK: function(n, k) {
    const factorial = function(num) {
      let out = 1;
      for (let i = 2; i <= num; i++) out *= i;
      return out;
    };
    return factorial(n) / (factorial(k) * factorial(n - k));
  },

  /**
   * Handle file selection for encryption
   */
  choosePlaintextFile: function(evt) {
    $('#secretfilename').text($('#secretfile').val() || 'No file selected');
    const file = evt.target.files[0];
    if (!file) return;

    $('#decfilename').html('No file selected');
    $('#decrypt').unbind('click').addClass('disabled');

    const reader = new FileReader();
    reader.onload = function(evt) {
      keybearer.setFileName(file.name);
      keybearer.setFileType(file.type);
      kbp.kb.postMessage({
        f: 'setPlaintext',
        p: [evt.target.result, file.name, file.type]
      });
    };
    keybearer.setPlaintext([]);
    reader.readAsArrayBuffer(file);
  },

  /**
   * Handle file selection for decryption
   */
  chooseEncryptedFile: function(evt) {
    $('#decfilename').text($('#decfile').val() || 'No file selected');
    const file = evt.target.files[0];
    if (!file) return;

    $('#secretfilename').html('No file selected');
    $('#encrypt').unbind('click').addClass('disabled');

    const reader = new FileReader();
    reader.onload = function(evt) {
      try {
        keybearer.setCipherJSON(evt.target.result);
        const n = keybearer.getNPasswords();
        const m = keybearer.getNumToUnlock();
        kbp.generateAllDecPass(n, m);
        $('#decrypt').attr('class', 'btn').click(kbp.decrypt);
      } catch (err) {
        alert('Error loading keybearer file:\n' + err);
        $('#decfileprogress').text('Error');
        throw err;
      }
    };
    reader.readAsBinaryString(file);
  },

  /**
   * Decrypt file with passwords
   */
  decrypt: function() {
    if (!keybearer.isCipherObjectReady()) {
      alert('You must load a file before decrypting it!');
      return;
    }

    try {
      const n = keybearer.getNPasswordsDecrypt();
      const m = keybearer.getNumToUnlock();
      const passwords = kbp.getMDecPass(n, m);

      keybearer.makeKeyCombinations(passwords, m);
      const gotKey = keybearer.decryptKeys();
      if (!gotKey) {
        alert('Could not decode key, check the passcodes');
        return;
      }

      keybearer.decryptCiphertext();
      const blob = new Blob([keybearer.getPlaintext()], {
        type: keybearer.getFileType()
      });
      const link = document.createElement('a');
      window.URL = window.URL || window.webkitURL;
      link.href = window.URL.createObjectURL(blob);
      link.download = keybearer.getFileName();
      link.innerHTML = 'Download decrypted ' + link.download;
      window.URL.revokeObjectURL($('#decdownloadlink > a').attr('href'));
      $('#decdownloadlink').empty().append(link);
    } catch (err) {
      alert('Error decrypting keybearer file:\n' + err);
      throw err;
    }
  },

  /**
   * Convert fraction to percentage
   */
  toPercent: function(fraction) {
    return Math.round(fraction * 100) + '%';
  },

  /**
   * Copy all passwords to modal
   */
  copyPasswords: function() {
    const passwords = kbp.getAllPass();
    for (let i = 0; i < passwords.length; i++) {
      passwords[i] = keybearer.normalizeString(passwords[i]);
    }
    $('#modalbody').html(passwords.join('<br>'));
    setTimeout(function() {
      kbp.selectText('modalbody');
    }, 500);
  },

  /**
   * Select text in element
   */
  selectText: function(element) {
    const doc = document;
    const text = doc.getElementById(element);
    let range, selection;

    if (doc.body.createTextRange) {
      // IE
      range = doc.body.createTextRange();
      range.moveToElementText(text);
      range.select();
    } else if (window.getSelection) {
      // Others
      selection = window.getSelection();
      range = doc.createRange();
      range.selectNodeContents(text);
      selection.removeAllRanges();
      selection.addRange(range);
    }
  }
};
