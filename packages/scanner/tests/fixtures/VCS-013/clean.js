const https = require("https");
const axios = require("axios");

const agent = new https.Agent({ rejectUnauthorized: true });

axios.get("https://api.example.com").then((res) => console.log(res.data));
