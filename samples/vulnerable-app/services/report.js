// 6) 프로시저 간 흐름 (CWE-78)
//    오염 생성 · 전달 · 위험 지점이 세 개의 함수로 나뉘어 있다.
//    패턴 매칭 방식으로는 어느 한 줄만 봐서는 판단할 수 없는 형태.

function getReportName(req) {
  return req.query.name;              // 오염 생성
}

function buildCommand(name) {
  return "generate-report " + name;   // 오염 전달 (param -> return)
}

function runReport(cmd) {
  child_process.exec(cmd);            // 위험 지점
}

function handleReport(req, res) {
  const name = getReportName(req);
  const cmd = buildCommand(name);
  runReport(cmd);
  res.send('started');
}

module.exports = { handleReport };
