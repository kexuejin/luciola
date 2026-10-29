// T3 验收（spec line 372）：ESM 用例，经 createRequire 加载既有 CJS 入口。
// 覆盖：惰性建立契约、经隧道 TCP 回环、统计行、同步拒绝（角色/非法目标/空规则/端口冲突）、
// 停转发释放端口可重绑、close() 暂停隧道（注册表保留 → active=false）。
import { createRequire } from 'node:module';
import net from 'node:net';
import dgram from 'node:dgram';
import assert from 'node:assert';

const require = createRequire(import.meta.url);
const luciola = require('../index.js');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitUntil(pred, ms, label) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (pred()) return;
    await sleep(50);
  }
  throw new Error(`超时(${ms}ms): ${label}`);
}

// 找一对连续空闲端口 L/L+1（默认 tunnel_port = securePort+1，两端口都要留出），
// 双栈探测（'::' 含 v4-mapped）。
function tryListen(port) {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.once('error', () => resolve(null));
    s.listen({ port, host: '::' }, () => resolve(s));
  });
}

async function tryPair(L) {
  const a = await tryListen(L);
  if (!a) return null;
  const b = await tryListen(L + 1);
  if (!b) { a.close(); return null; }
  a.close();
  b.close();
  return L;
}

async function freePortPair() {
  for (let i = 0; i < 80; i++) {
    const L = 20000 + Math.floor(Math.random() * 30000);
    const got = await tryPair(L);
    if (got !== null) return got;
  }
  throw new Error('找不到连续空闲端口对 L/L+1');
}

function tcpRoundtrip(port, payload, timeoutMs = 2000) {
  return new Promise((resolve) => {
    const sock = net.connect({ port, host: '127.0.0.1' });
    let buf = Buffer.alloc(0);
    let done = false;
    const finish = (ok) => {
      if (done) return;
      done = true;
      try { sock.destroy(); } catch { /* ignore */ }
      resolve(ok);
    };
    sock.setTimeout(timeoutMs, () => finish(false));
    sock.on('error', () => finish(false));
    sock.on('connect', () => sock.write(payload));
    sock.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      if (buf.length >= payload.length) finish(buf.equals(payload));
    });
    sock.on('close', () => finish(false));
  });
}

async function waitPortFree(port, ms = 15000) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    const s = net.createServer();
    const ok = await new Promise((res) => {
      s.once('error', () => res(false));
      s.listen({ port, host: '127.0.0.1' }, () => res(true));
    });
    if (ok) {
      await new Promise((res) => s.close(res));
      return true;
    }
    await sleep(100);
  }
  return false;
}

async function main() {
  // —— 建立消息链路（端口 L，隧道默认占 L+1）——
  const L = await freePortPair();
  const idSrv = luciola.identityFromSeed(Buffer.alloc(32, 2));
  const idDial = luciola.identityFromSeed(Buffer.alloc(32, 1));

  const srvEv = [];
  const dialEv = [];
  const srv = new luciola.SecureChannel(idSrv.seed);
  const dial = new luciola.SecureChannel(idDial.seed);
  srv.listen(L, null, (ev) => { if (ev.state) srvEv.push(ev); });
  dial.connect(['127.0.0.1'], L, idSrv.publicKey, true, (ev) => { if (ev.state) dialEv.push(ev); });
  await waitUntil(() => dial.isConnected(), 20000, '消息链路 connected');
  await sleep(200);
  const countOf = (arr, state) => arr.filter((e) => e.state === state).length;
  const lastDetail = (arr, state) => { const m = arr.filter((e) => e.state === state); return m.length ? (m[m.length - 1].detail ?? '') : ''; };
  const hasDetailPrefix = (arr, state, prefix) =>
    arr.some((e) => e.state === state && (e.detail ?? '').startsWith(prefix));
  console.log('  · 消息链路 connected (L=%d)', L);

  // —— 惰性契约（spec line 362）：两侧在各自首次注册前不得绑定隧道 ——
  assert.strictEqual(dial.forwardStats().length, 0, '发起端注册前 stats 应为空');
  assert.strictEqual(srv.forwardStats().length, 0, '响应端注册前 stats 应为空（惰性/端点未启用）');

  // —— 响应端先启用端点（spec：惰性建立按侧）——
  const srvErr0 = countOf(srvEv, 'error');
  assert.strictEqual(
    srv.enableForwardEndpoint([{ host: '127.0.0.1', portFrom: 1, portTo: 65535, udp: false }]),
    true,
    '响应端 enableForwardEndpoint 应成功',
  );

  // —— 同步拒绝（spec line 363：false + on_state("error")，不静默）——
  const dialErr0 = countOf(dialEv, 'error');
  assert.strictEqual(
    dial.enableForwardEndpoint([{ host: '127.0.0.1', portFrom: 1, portTo: 65535, udp: false }]),
    false,
    '发起端启用端点应被角色拒绝',
  );
  assert.strictEqual(
    // v2：'not-an-ip' 是合法主机名字符串（解析在对端）；纯数字串才被拒
    dial.startLocalForward(0, '1.2.3.999', 80),
    false,
    '非法目标（纯数字串）应被同步拒绝',
  );
  assert.strictEqual(srv.enableForwardEndpoint([]), false, '空 rules = 全拒绝，且同步报错');

  // 占一个端口制造转发绑定冲突
  const conflict = net.createServer();
  await new Promise((res, rej) => { conflict.once('error', rej); conflict.listen(0, '127.0.0.1', res); });
  const conflictPort = conflict.address().port;
  assert.strictEqual(
    dial.startLocalForward(conflictPort, '127.0.0.1', 9),
    false,
    '端口冲突应同步返回 false',
  );
  conflict.close();
  await sleep(300); // tsfn NonBlocking：给回调一个 tick 到达
  assert.strictEqual(countOf(dialEv, 'error'), dialErr0 + 3, '发起端应同步收到 3 条 error');
  assert.ok(hasDetailPrefix(dialEv, 'error', 'invalid target: '), '非法目标 detail 前缀 invalid target:');
  assert.ok(hasDetailPrefix(dialEv, 'error', 'forward_bind_failed: '), '绑定冲突 detail 前缀 forward_bind_failed:');
  assert.strictEqual(countOf(srvEv, 'error'), srvErr0 + 1, '响应端空规则应收到 1 条 error');
  assert.ok(hasDetailPrefix(srvEv, 'error', 'invalid forward rule: '), '空规则 detail 前缀 invalid forward rule:');
  assert.strictEqual(dial.forwardStats().length, 0, '同步拒绝不得留下 stats 行');
  console.log('  · 同步拒绝三连 + 端口冲突 已验证');

  // —— 端到端经隧道回环 ——
  const dialErrAfterReject = countOf(dialEv, 'error');
  const echo = net.createServer((s) => s.pipe(s));
  await new Promise((res) => echo.listen(0, '127.0.0.1', res));
  const echoPort = echo.address().port;
  assert.strictEqual(
    dial.startLocalForward(0, '127.0.0.1', echoPort),
    true,
    '发起端 startLocalForward 应成功',
  );
  const payload = Buffer.from('tunnel-hello-' + Date.now());
  let localPort = 0;
  await waitUntil(() => {
    const rows = dial.forwardStats();
    if (rows.length === 1 && rows[0].listenPort > 0) { localPort = rows[0].listenPort; return true; }
    return false;
  }, 5000, '本地转发行出现并给出监听端口');
  let ok = false;
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline && !ok) {
    ok = await tcpRoundtrip(localPort, payload);
    if (!ok) await sleep(200);
  }
  assert.ok(ok, '经隧道的 TCP 回环应成功');
  console.log('  · 经隧道 TCP 回环成功 (localPort=%d)', localPort);

  // —— 统计行 ——
  const dialRows = dial.forwardStats();
  assert.strictEqual(dialRows.length, 1, '发起端应恰有一行');
  assert.strictEqual(dialRows[0].active, true, '本地转发行 active');
  assert.ok(dialRows[0].channelsTotal >= 1, 'channelsTotal >= 1');
  assert.strictEqual(dialRows[0].dialDenied, 0, '正常转发无 ACL 拦截');
  const srvRows = srv.forwardStats();
  assert.strictEqual(srvRows.length, 1, '响应端应恰有一行');
  assert.ok(srvRows[0].channelsTotal >= 1, '端点行 channelsTotal >= 1');
  assert.strictEqual(
    countOf(dialEv, 'error'),
    dialErrAfterReject,
    '隧道建立与回环期间不得新增 error',
  );
  assert.strictEqual(countOf(dialEv, 'connected'), 1, '消息链路恰好一次 connected');
  assert.strictEqual(countOf(dialEv, 'closed'), 0, '未断链 closed=0');
  console.log('  · 统计行与事件计数已验证');

  // —— 停止释放端口 + 可重绑 ——
  assert.strictEqual(dial.stopLocalForward(localPort), true, '停止转发应成功');
  assert.strictEqual(dial.stopLocalForward(localPort), false, '重复停止返回 false');
  assert.strictEqual(dial.forwardStats().length, 0, '停止后 stats 行清空');
  assert.ok(await waitPortFree(localPort), 'stop 后端口应释放');
  assert.strictEqual(dial.startLocalForward(localPort, '127.0.0.1', echoPort), true, '同端口重绑应成功');
  let reok = false;
  const dl2 = Date.now() + 30000;
  while (Date.now() < dl2 && !reok) {
    reok = await tcpRoundtrip(localPort, payload);
    if (!reok) await sleep(200);
  }
  assert.ok(reok, '重绑后回环应恢复');
  console.log('  · 停止释放端口并成功重绑');

  // —— close() 暂停隧道：注册表保留 → active=false ——
  dial.close();
  await waitUntil(() => dial.forwardStats().length === 1 && !dial.forwardStats()[0].active, 15000, 'close 后行保留且 active=false');
  let refused = false;
  const dl3 = Date.now() + 15000;
  while (Date.now() < dl3 && !refused) {
    refused = !(await tcpRoundtrip(localPort, payload));
    if (!refused) await sleep(200);
  }
  assert.ok(refused, 'close 后本地端口不再转发');
  console.log('  · close() 暂停隧道，注册表保留 active=false');

  srv.close();
  echo.close();
  console.log('  · T3 验收通过');
}

// —— T4 (v2)：UDP 转发 + remote forward + keepalive/主机名控制面 ——
async function mainV2() {
  const L = await freePortPair();
  const idSrv = luciola.identityFromSeed(Buffer.alloc(32, 2));
  const idDial = luciola.identityFromSeed(Buffer.alloc(32, 1));

  const srvEv = [];
  const dialEv = [];
  const srv = new luciola.SecureChannel(idSrv.seed);
  const dial = new luciola.SecureChannel(idDial.seed);
  srv.listen(L, null, (ev) => { if (ev.state) srvEv.push(ev); });
  dial.connect(['127.0.0.1'], L, idSrv.publicKey, true, (ev) => { if (ev.state) dialEv.push(ev); });
  await waitUntil(() => dial.isConnected(), 20000, '消息链路 connected');
  console.log('  · [v2] 消息链路 connected');

  // keepalive 调整（下一次隧道重建生效；0 = 关闭）
  dial.setTunnelKeepalive(5000, 15000);
  srv.setTunnelKeepalive(0, 0);

  // —— UDP 转发（NAT 式映射）——
  const udpEcho = dgram.createSocket('udp4');
  const udpUpPort = await new Promise((res) => udpEcho.bind(0, '127.0.0.1', () => res(udpEcho.address().port)));
  udpEcho.on('message', (msg, rinfo) => udpEcho.send(msg, rinfo.port, rinfo.address));
  assert.strictEqual(
    srv.enableForwardEndpoint([{ host: '127.0.0.1', portFrom: 1, portTo: 65535, udp: true }]),
    true, '含 udp 规则的端点应启用',
  );
  const udpLocalPort = 20000 + Math.floor(Math.random() * 30000);
  assert.strictEqual(dial.startUdpForward(udpLocalPort, '127.0.0.1', udpUpPort), true, 'UDP 转发注册');
  const sock = dgram.createSocket('udp4');
  const udpOk = await new Promise((res) => {
    let tries = 0;
    const tick = () => {
      tries += 1;
      if (tries > 60) return res(false);
      sock.send('udp-e2e', udpLocalPort, '127.0.0.1', () => {});
      const t = setTimeout(() => tick(), 300);
      sock.once('message', (msg) => { clearTimeout(t); res(msg.toString() === 'udp-e2e'); });
    };
    tick();
  });
  assert.ok(udpOk, '经隧道的 UDP 回环应成功');
  const udpRow = dial.forwardStats().find((s) => s.kind === 'udp_local');
  assert.ok(udpRow && udpRow.active, 'udp_local 行 active');
  assert.strictEqual(dialEv.filter((e) => e.state === 'error').length, 0, 'UDP happy path 零 error');
  console.log('  · [v2] UDP 转发回环通过');
  dial.stopUdpForward(udpLocalPort);
  sock.close();
  udpEcho.close();

  // —— remote forward（-R）：默认拒绝 → 启用后回环 ——
  const echo = net.createServer((c) => { c.on('data', (d) => c.write(d)); });
  const echoPort = await new Promise((res) => echo.listen(0, '127.0.0.1', () => res(echo.address().port)));
  const remotePort = 20000 + Math.floor(Math.random() * 30000);
  assert.strictEqual(srv.startRemoteForward(remotePort, '127.0.0.1', echoPort), true, 'remote forward 注册');
  // 隧道懒建立需要 Dial 侧也有工作：哑本地转发
  const dummyUp = 20000 + Math.floor(Math.random() * 30000);
  const dummyPort = 20000 + Math.floor(Math.random() * 30000);
  assert.strictEqual(dial.startLocalForward(dummyPort, '127.0.0.1', dummyUp), true);
  // 默认拒绝：连接被关闭而非回显
  let denied = false;
  {
    const dl = Date.now() + 60000;
    while (Date.now() < dl && !denied) {
      denied = await new Promise((res) => {
        // 拒绝的判定 = 对端主动关闭（RST 或干净 FIN）；ECONNREFUSED = 监听尚未
        // 绑定（懒建立）→ 交给 wait_until 重试；收到数据 = 拒绝失效。
        const c = net.connect({ port: remotePort, host: '127.0.0.1' });
        let settled = false;
        const done = (v) => { if (!settled) { settled = true; clearTimeout(t); res(v); } };
        const t = setTimeout(() => { c.destroy(); done(false); }, 8000);
        c.on('error', (e) => done(e.code === 'ECONNRESET'));
        c.on('connect', () => c.write('x'));
        c.on('data', () => done(false));
        c.on('close', () => done(true));
      });
      if (!denied) await sleep(300);
    }
  }
  assert.ok(denied, '未启用 remote endpoint 时拨入必须被拒绝');
  assert.strictEqual(dial.enableRemoteEndpoint([{ host: '127.0.0.1', portFrom: 1, portTo: 65535, udp: false }]), true);
  let rok = false;
  const dl2 = Date.now() + 30000;
  while (Date.now() < dl2 && !rok) {
    rok = await tcpRoundtrip(remotePort, Buffer.from('remote-e2e'));
    if (!rok) await sleep(300);
  }
  assert.ok(rok, 'remote forward 回环应成功');
  assert.ok(
    srv.forwardStats().some((s) => s.kind === 'remote' && s.active),
    'remote 行 active',
  );
  assert.ok(
    dial.forwardStats().some((s) => s.kind === 'remote_endpoint'),
    'remote_endpoint 行存在',
  );
  console.log('  · [v2] remote forward 默认拒绝 + 回环通过');

  dial.stopLocalForward(dummyPort);
  srv.stopRemoteForward(remotePort);
  dial.close();
  srv.close();
  echo.close();
  console.log('forward.test.mjs: ALL PASS');
}

main()
  .then(mainV2)
  .then(() => process.exit(0))
  .catch((e) => {
    console.error(e);
    process.exit(1);
  });