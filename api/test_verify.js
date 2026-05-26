const axios = require('axios');

async function test() {
  const sbomID = 'realworld-demo-15';
  
  // fetch original
  const resSboms = await axios.get('http://localhost:3000/api/sboms', {
      headers: { 'x-user-id': 'admin', 'x-user-role': 'admin' }
  });
  const original = resSboms.data.sboms.find(s => s.sbom_id === sbomID);
  
  // clone and modify
  const modified = JSON.parse(JSON.stringify(original.sbom_json));
  // modify version of first component
  modified.components[0].version = "9.9.9";

  // submit to verify
  try {
    const resVerify = await axios.post('http://localhost:3000/api/verify', {
      sbomID: sbomID,
      sbom: JSON.stringify(modified)
    }, {
      headers: { 'x-user-id': 'admin', 'x-user-role': 'admin' }
    });
    console.log("Verify Result:", require('util').inspect(resVerify.data.verification, {depth: null}));
  } catch (err) {
    console.log("Error:", err.response ? err.response.data : err.message);
  }
}

test();
