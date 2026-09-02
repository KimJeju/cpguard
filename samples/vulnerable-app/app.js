const express = require('express');
const child_process = require('child_process');
const fs = require('fs');
const app = express();

// 1) 명령 주입 (CWE-78)
app.get('/ping', function (req, res) {
  const host = req.query.host;
  const cmd = "ping -c 1 " + host;
  child_process.exec(cmd);
  res.send('ok');
});

// 2) 경로 조작 (CWE-22)
app.get('/file', function (req, res) {
  const name = req.query.name;
  fs.readFile(name, function (e, data) { res.send(data); });
});

// 3) 안전 — 정제됨 (탐지되면 오탐)
app.get('/safe', function (req, res) {
  const clean = path.basename(req.query.name);
  fs.readFile(clean, function (e, data) { res.send(data); });
});

module.exports = app;
