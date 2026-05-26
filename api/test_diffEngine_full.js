const { analyzeTampering } = require('./src/utils/sbomDiffEngine');

const original = {
  "bomFormat": "CycloneDX",
  "components": [
    { "name": "express", "version": "4.17.1", "purl": "pkg:npm/express@4.17.1" }
  ]
};

const submitted = {
  "bomFormat": "CycloneDX",
  "components": [
    { "name": "express", "version": "4.17.2", "purl": "pkg:npm/express@4.17.1" }
  ]
};

console.log("Only version modified:", analyzeTampering(original, submitted).tamperType);

const submitted2 = {
  "bomFormat": "CycloneDX",
  "components": [
    { "name": "express", "version": "4.17.2", "purl": "pkg:npm/express@4.17.2" }
  ]
};

console.log("Version AND purl modified:", analyzeTampering(original, submitted2).tamperType);
