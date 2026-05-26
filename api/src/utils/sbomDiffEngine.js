'use strict';

// ─── Stable key helpers ───────────────────────────────────────────────────────

/**
 * Returns the primary stable key for a component.
 * Priority: purl > bom-ref > name
 * Note: purl often encodes the version, so we also track the base purl (without @version)
 * so that version bumps still resolve to the same logical component.
 */
function getStableKey(comp) {
  if (comp.purl) {
    // Strip the version suffix from purl so pkg:npm/express@4.17.1 and pkg:npm/express@4.17.2
    // resolve to the same logical component key.
    return comp.purl.replace(/@[^@?#]*/, '');
  }
  if (comp['bom-ref']) {
    // bom-ref can also contain version; strip trailing @<version> pattern
    return comp['bom-ref'].replace(/@[^@]*$/, '');
  }
  return 'name:' + (comp.name || 'Unknown');
}

function buildComponentMap(sbom) {
  var map = new Map();
  var comps = (sbom && sbom.components && Array.isArray(sbom.components)) ? sbom.components : [];

  for (var i = 0; i < comps.length; i++) {
    var comp = comps[i];
    if (!comp || typeof comp !== 'object') continue;
    var key = getStableKey(comp);
    if (!map.has(key)) {
      map.set(key, []);
    }
    map.get(key).push({
      name: comp.name || 'Unknown',
      version: comp.version || null,
      purl: comp.purl || null,
      bomRef: comp['bom-ref'] || null
    });
  }
  return map;
}

// ─── Metadata diff helpers ────────────────────────────────────────────────────

/**
 * Compares top-level metadata fields that are NOT components.
 * Returns a list of changed fields with fieldPath, originalValue, modifiedValue.
 */
function diffMetadataFields(originalSbom, submittedSbom) {
  var changedFields = [];

  // Fields to check at top level
  var topLevelFields = ['serialNumber', 'version', 'specVersion', 'bomFormat'];
  for (var i = 0; i < topLevelFields.length; i++) {
    var field = topLevelFields[i];
    var origVal = originalSbom[field];
    var subVal = submittedSbom[field];
    if (JSON.stringify(origVal) !== JSON.stringify(subVal)) {
      changedFields.push({
        fieldPath: field,
        originalValue: origVal !== undefined ? String(origVal) : null,
        modifiedValue: subVal !== undefined ? String(subVal) : null,
        changeType: 'FIELD_LEVEL_METADATA_MODIFICATION'
      });
    }
  }

  // metadata.component block
  var origMeta = (originalSbom.metadata && typeof originalSbom.metadata === 'object') ? originalSbom.metadata : {};
  var subMeta = (submittedSbom.metadata && typeof submittedSbom.metadata === 'object') ? submittedSbom.metadata : {};

  var metaSubFields = ['timestamp'];
  for (var j = 0; j < metaSubFields.length; j++) {
    var mf = metaSubFields[j];
    if (JSON.stringify(origMeta[mf]) !== JSON.stringify(subMeta[mf])) {
      changedFields.push({
        fieldPath: 'metadata.' + mf,
        originalValue: origMeta[mf] !== undefined ? String(origMeta[mf]) : null,
        modifiedValue: subMeta[mf] !== undefined ? String(subMeta[mf]) : null,
        changeType: 'FIELD_LEVEL_METADATA_MODIFICATION'
      });
    }
  }

  // metadata.component (main component described by the SBOM)
  var origMetaComp = origMeta.component && typeof origMeta.component === 'object' ? origMeta.component : null;
  var subMetaComp = subMeta.component && typeof subMeta.component === 'object' ? subMeta.component : null;

  var metaCompFields = ['name', 'version', 'type', 'supplier', 'publisher', 'licenses'];
  if (origMetaComp || subMetaComp) {
    for (var k = 0; k < metaCompFields.length; k++) {
      var cf = metaCompFields[k];
      var origCv = origMetaComp ? origMetaComp[cf] : undefined;
      var subCv = subMetaComp ? subMetaComp[cf] : undefined;
      if (JSON.stringify(origCv) !== JSON.stringify(subCv)) {
        changedFields.push({
          fieldPath: 'metadata.component.' + cf,
          originalValue: origCv !== undefined ? JSON.stringify(origCv) : null,
          modifiedValue: subCv !== undefined ? JSON.stringify(subCv) : null,
          changeType: 'FIELD_LEVEL_METADATA_MODIFICATION'
        });
      }
    }
  }

  return changedFields;
}

// ─── Main analysis ────────────────────────────────────────────────────────────

function analyzeTampering(originalSbom, submittedSbom) {
  var origMap = buildComponentMap(originalSbom);
  var subMap = buildComponentMap(submittedSbom);

  var affectedComponents = [];
  var changedFields = [];
  var actionsSeen = new Set();

  // ── Pass 1: Find removals and version modifications (orig → sub) ──────────
  origMap.forEach(function(origComps, key) {
    var subComps = subMap.get(key) || [];

    if (subComps.length === 0) {
      // Key not found in submitted → removal
      for (var i = 0; i < origComps.length; i++) {
        affectedComponents.push({
          component: origComps[i].name,
          originalVersion: origComps[i].version,
          modifiedVersion: null,
          status: 'Removed',
          changeType: 'COMPONENT_REMOVAL'
        });
        actionsSeen.add('COMPONENT_REMOVAL');
      }
    } else {
      // Key found — compare versions
      if (origComps.length === 1 && subComps.length === 1) {
        var origC = origComps[0];
        var subC = subComps[0];
        if (origC.version !== subC.version) {
          affectedComponents.push({
            component: origC.name,
            originalVersion: origC.version,
            modifiedVersion: subC.version,
            status: 'Modified',
            changeType: 'VERSION_MODIFICATION'
          });
          actionsSeen.add('VERSION_MODIFICATION');
        }
      } else {
        var unmatchedOrig = [];
        var unmatchedSub = subComps.slice();

        for (var i = 0; i < origComps.length; i++) {
          var oC = origComps[i];
          var matchIdx = unmatchedSub.findIndex(function(sC) { return sC.version === oC.version; });
          if (matchIdx >= 0) {
            unmatchedSub.splice(matchIdx, 1);
          } else {
            unmatchedOrig.push(oC);
          }
        }

        var minLen = Math.min(unmatchedOrig.length, unmatchedSub.length);
        for (var i = 0; i < minLen; i++) {
          affectedComponents.push({
            component: unmatchedOrig[i].name,
            originalVersion: unmatchedOrig[i].version,
            modifiedVersion: unmatchedSub[i].version,
            status: 'Modified',
            changeType: 'VERSION_MODIFICATION'
          });
          actionsSeen.add('VERSION_MODIFICATION');
        }
        for (var i = minLen; i < unmatchedOrig.length; i++) {
          affectedComponents.push({
            component: unmatchedOrig[i].name,
            originalVersion: unmatchedOrig[i].version,
            modifiedVersion: null,
            status: 'Removed',
            changeType: 'COMPONENT_REMOVAL'
          });
          actionsSeen.add('COMPONENT_REMOVAL');
        }
        for (var i = minLen; i < unmatchedSub.length; i++) {
          affectedComponents.push({
            component: unmatchedSub[i].name,
            originalVersion: null,
            modifiedVersion: unmatchedSub[i].version,
            status: 'Added',
            changeType: 'COMPONENT_INJECTION'
          });
          actionsSeen.add('COMPONENT_INJECTION');
        }
      }
    }
  });

  // ── Pass 2: Find injections (sub keys not in orig) ────────────────────────
  subMap.forEach(function(subComps, key) {
    if (!origMap.has(key)) {
      for (var i = 0; i < subComps.length; i++) {
        affectedComponents.push({
          component: subComps[i].name,
          originalVersion: null,
          modifiedVersion: subComps[i].version,
          status: 'Added',
          changeType: 'COMPONENT_INJECTION'
        });
        actionsSeen.add('COMPONENT_INJECTION');
      }
    }
  });

  // ── Pass 3: Fuzzy name-based fallback for unmatched removals/injections ───
  // If we have both removals and injections, try to pair them by name.
  // This catches cases where purl/bom-ref version suffix changed but name is same.
  if (actionsSeen.has('COMPONENT_REMOVAL') && actionsSeen.has('COMPONENT_INJECTION')) {
    var removals = affectedComponents.filter(function(c) { return c.status === 'Removed'; });
    var injections = affectedComponents.filter(function(c) { return c.status === 'Added'; });
    var kept = affectedComponents.filter(function(c) { return c.status === 'Modified'; });

    var resolvedRemovals = new Set();
    var resolvedInjections = new Set();
    var merged = [];

    for (var ri = 0; ri < removals.length; ri++) {
      var remComp = removals[ri];
      // Find a matching injection by name
      for (var ii = 0; ii < injections.length; ii++) {
        if (resolvedInjections.has(ii)) continue;
        var injComp = injections[ii];
        if (injComp.component === remComp.component) {
          // Same name — this is a version modification, not a removal+injection
          merged.push({
            component: remComp.component,
            originalVersion: remComp.originalVersion,
            modifiedVersion: injComp.modifiedVersion,
            status: 'Modified',
            changeType: 'VERSION_MODIFICATION'
          });
          resolvedRemovals.add(ri);
          resolvedInjections.add(ii);
          break;
        }
      }
    }

    if (merged.length > 0) {
      // Rebuild affectedComponents without the resolved pairs, plus merged ones
      var remaining = [];
      for (var ri = 0; ri < removals.length; ri++) {
        if (!resolvedRemovals.has(ri)) remaining.push(removals[ri]);
      }
      for (var ii = 0; ii < injections.length; ii++) {
        if (!resolvedInjections.has(ii)) remaining.push(injections[ii]);
      }
      affectedComponents = kept.concat(merged).concat(remaining);

      // Recompute actionsSeen
      actionsSeen.clear();
      for (var ai = 0; ai < affectedComponents.length; ai++) {
        actionsSeen.add(affectedComponents[ai].changeType);
      }
    }
  }

  // ── Pass 4: Metadata diff (only if no component-level changes OR as supplement) ─
  if (originalSbom && typeof originalSbom === 'object' &&
      submittedSbom && typeof submittedSbom === 'object') {
    changedFields = diffMetadataFields(originalSbom, submittedSbom);
    if (changedFields.length > 0) {
      actionsSeen.add('FIELD_LEVEL_METADATA_MODIFICATION');
    }
  }

  // ── Priority classification ───────────────────────────────────────────────
  var primaryType = 'OTHER_MODIFICATION';
  if (actionsSeen.has('COMPONENT_INJECTION')) {
    primaryType = 'COMPONENT_INJECTION';
  } else if (actionsSeen.has('COMPONENT_REMOVAL')) {
    primaryType = 'COMPONENT_REMOVAL';
  } else if (actionsSeen.has('VERSION_MODIFICATION')) {
    primaryType = 'VERSION_MODIFICATION';
  } else if (actionsSeen.has('FIELD_LEVEL_METADATA_MODIFICATION')) {
    primaryType = 'FIELD_LEVEL_METADATA_MODIFICATION';
  }

  // ── Build integrity failure reason ────────────────────────────────────────
  var integrityFailureReason;
  if (affectedComponents.length > 0 && changedFields.length > 0) {
    integrityFailureReason =
      'Component-level changes detected (' + affectedComponents.length + ') and metadata field changes detected (' + changedFields.length + ').';
  } else if (affectedComponents.length > 0) {
    integrityFailureReason =
      'Component-level changes detected: ' + affectedComponents.length + ' component(s) ' +
      Array.from(actionsSeen).join(', ') + '.';
  } else if (changedFields.length > 0) {
    integrityFailureReason =
      'No component-level changes found. Metadata field modifications detected: ' +
      changedFields.map(function(f) { return f.fieldPath; }).join(', ') + '.';
  } else {
    integrityFailureReason =
      'Hash mismatch confirmed. No component-level or metadata field differences were identifiable. ' +
      'The modification may be in structural encoding, whitespace, or field ordering.';
  }

  // ── Build summary ─────────────────────────────────────────────────────────
  var summary;
  if (affectedComponents.length > 0 || changedFields.length > 0) {
    var parts = [];
    if (affectedComponents.length > 0) {
      parts.push(affectedComponents.length + ' component change(s)');
    }
    if (changedFields.length > 0) {
      parts.push(changedFields.length + ' metadata field change(s)');
    }
    summary = 'Detected ' + parts.join(' and ') + '.';
  } else {
    summary = 'Hash mismatch detected, but no specific differences could be identified automatically.';
  }

  var tamperReport = {
    primaryTamperType: primaryType,
    allClassifications: Array.from(actionsSeen),
    summary: summary,
    integrityFailureReason: integrityFailureReason,
    componentActions: affectedComponents,
    metadataChanges: changedFields
  };

  return {
    tamperDetected: true,
    tamperType: primaryType,
    integrityFailureReason: integrityFailureReason,
    affectedComponents: affectedComponents,
    changedFields: changedFields,
    tamperReport: tamperReport
  };
}

module.exports = {
  analyzeTampering: analyzeTampering
};
