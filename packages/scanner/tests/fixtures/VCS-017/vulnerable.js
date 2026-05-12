const express = require("express");
const fs = require("fs");
const path = require("path");

const app = express();

app.get("/download", (req, res) => {
  const filename = req.query.file;
  res.sendFile(filename);
});

app.get("/read", (req, res) => {
  fs.readFile(req.query.path, (err, data) => {
    res.send(data);
  });
});

app.post("/save", (req, res) => {
  const dest = path.join("/data", req.body.dest);
  fs.writeFile(dest, req.body.content, (err) => {
    res.send("ok");
  });
});
