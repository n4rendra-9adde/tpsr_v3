const axios = require('axios');

async function test() {
  try {
    const res = await axios.get('http://localhost:3000/api/sboms', {
      headers: {
        'x-user-id': 'admin',
        'x-user-role': 'admin'
      }
    });
    console.log(res.data.sboms.map(s => s.sbomID));
  } catch (err) {
    console.log("Error:", err.message);
  }
}

test();
