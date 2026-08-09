'use strict';
const fs = require('fs');
const path = require('path');

describe('CAECTD Model Validation', () => {
  it('loads valid JSON for the model and decision matrix', () => {
    const modelPath = path.join(__dirname, '../../../../docs/models/caectd-model.v0.1.json');
    const matrixPath = path.join(__dirname, '../../../../docs/models/caectd-decision-matrix.v0.1.json');
    
    expect(fs.existsSync(modelPath)).toBe(true);
    expect(fs.existsSync(matrixPath)).toBe(true);

    const model = JSON.parse(fs.readFileSync(modelPath, 'utf8'));
    const matrix = JSON.parse(fs.readFileSync(matrixPath, 'utf8'));

    expect(model.modelId).toBe('CAECTD');
    expect(model.modelVersion).toBe('0.1');
    expect(Array.isArray(matrix)).toBe(true);
    expect(matrix.length).toBeGreaterThan(0);
  });
});
