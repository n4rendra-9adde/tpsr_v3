const { analyzeTampering } = require('./src/utils/sbomDiffEngine');

const original = {
  components: [
    { name: "express", version: "4.17.1", "bom-ref": "pkg:npm/express@4.17.1" }
  ]
};

const submitted = {
  components: [
    { name: "express", version: "4.17.2", "bom-ref": "pkg:npm/express@4.17.1" }
  ]
};

const res = analyzeTampering(original, submitted);
console.log(res);
