const { analyzeTampering } = require('./src/utils/sbomDiffEngine');

const original = {
  components: [
    { name: "express", version: "4.17.1" }
  ]
};

const submitted = {
  components: [
    { name: "express", version: "4.17.2" }
  ]
};

console.log(analyzeTampering(original, submitted).tamperType);
