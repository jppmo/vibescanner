const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const BASE = "/data";

app.get("/download/:id", (req, res) => {
  // Look up real filename via opaque ID
  const record = db.lookup(req.params.id);
  if (!record) return res.status(404).send("not found");
  res.sendFile(path.join(BASE, record.filename));
});

app.post("/upload", (req, res) => {
  const newName = crypto.randomUUID() + ".bin";
  fs.writeFile(path.join(BASE, newName), req.body.content, () => {
    res.send(newName);
  });
});
