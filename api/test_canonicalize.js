const { canonicalizeSBOM } = require('./src/utils/canonicalize');

try {
  canonicalizeSBOM("\uFEFF{\"components\":[]}");
  console.log("OK");
} catch(e) {
  console.log(e.message);
}
