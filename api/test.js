const axios = require('axios');

async function test() {
  try {
    const res = await axios.post('http://localhost:3000/api/review-pending', {
      sbomID: 'realworld-demo-15'
    }, {
      headers: {
        'x-user-id': 'admin',
        'x-user-role': 'admin'
      }
    });
    console.log("Success:", res.data);
  } catch (err) {
    console.log("Error:", err.response ? err.response.data : err.message);
  }
}

test();
