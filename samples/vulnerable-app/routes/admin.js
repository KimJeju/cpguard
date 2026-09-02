// 4) 코드 주입 (CWE-94)
function runCalc(req, res) {
  const expr = req.body.expr;
  const result = eval(expr);
  res.send(String(result));
}

// 5) SQL 주입 (CWE-89)
function findUser(req, res) {
  const uid = req.params.id;
  db.query("SELECT * FROM users WHERE id = " + uid);
}
