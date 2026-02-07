/**
 * kb-worker.js - Web Worker for Keybearer encryption operations
 *
 * Handles encryption in a separate thread to avoid blocking the UI
 */

import keybearer from './kb.js';

// Initialize entropy for the worker
// (In v2, crypto.getRandomValues() is always available, no seeding needed)

self.onmessage = function(event) {
  const data = event.data;
  const functionName = data.f;
  const params = data.p || [];
  const hasCallback = data.c;

  // If function expects a callback, add progress reporter
  if (hasCallback) {
    params.push(function(progress) {
      self.postMessage({ f: functionName, c: progress });
    });
  }

  // Call the keybearer function
  const result = keybearer[functionName].apply(keybearer, params);

  // Send result back if not undefined
  if (result !== undefined) {
    self.postMessage({ f: functionName, r: result });
  }
};
