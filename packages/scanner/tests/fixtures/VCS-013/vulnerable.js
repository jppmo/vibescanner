const https = require("https");
const axios = require("axios");

const agent = new https.Agent({ rejectUnauthorized: false });

axios.get("https://api.example.com", {
  httpsAgent: new https.Agent({ rejectUnauthorized: false }),
});

const config = {
  url: "https://api.example.com",
  agent: { rejectUnauthorized: false },
};
