// Pure async-controller tests in Node; no browser, local-site access or rendering.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../qsploit/static/app.js'), 'utf8');
function deferred() {
  let resolve; const promise = new Promise(r => { resolve = r; });
  return { promise, resolve };
}
function controller() {
  const nodes = new Map();
  const element = selector => {
    if (!nodes.has(selector)) nodes.set(selector, { children: [], addEventListener() {},
      replaceChildren(...items) { this.children = items; }, classList: {add() {}, remove() {}, toggle() {}},
      setAttribute() {}, append() {}, dataset: {} });
    return nodes.get(selector);
  };
  const context = vm.createContext({document: {querySelector: element, querySelectorAll: () => [], createElement: () => element(Symbol())},
    fetch: () => new Promise(() => {}), setTimeout, clearTimeout, console, TextDecoder, Uint8Array,
    atob, File: class {}, URL});
  vm.runInContext(source, context);
  vm.runInContext('globalThis.stateForTest = state; renderCapture = () => {}; renderDetail = () => {}; renderMessages = () => {};', context);
  return { context, state: context.stateForTest, element };
}

test('late response cannot replace the most recently selected HTTP exchange', async () => {
  const {context, state} = controller();
  state.selected = 'A';
  const first = deferred(), second = deferred();
  context.api = path => path.endsWith('/0') ? first.promise : second.promise;
  const one = context.loadExchange(0), two = context.loadExchange(1);
  second.resolve({index: 1, captured: 'new selection'}); await two;
  first.resolve({index: 0, captured: 'late response'}); await one;
  assert.equal(state.exchange.index, 1);
});

test('a recovery response for A does not render under newly selected B', async () => {
  const {context, state, element} = controller();
  state.selected = 'A';
  const post = deferred(); let rendered = 0;
  context.api = () => post.promise;
  context.renderJob = () => { rendered++; };
  context.poll = async () => {};
  const recovering = element('#recover').onclick();
  state.selected = 'B';
  post.resolve({id: 'job-A', session_id: 'A'}); await recovering;
  assert.equal(rendered, 0);
  assert.equal(state.job, null);
});

test('reselecting a running session reuses its poll and stale completion cannot unlock a newer job', async () => {
  const {context, state} = controller();
  state.capture = {id: 'capture-A'};
  const job = deferred(), refresh = deferred(); let jobReads = 0;
  context.api = path => {
    if (path.startsWith('/api/jobs/')) { jobReads++; return job.promise; }
    return refresh.promise;
  };
  const first = context.poll('job-A', false), duplicate = context.poll('job-A', false);
  assert.equal(first, duplicate); assert.equal(jobReads, 1);
  job.resolve({id: 'job-A', session_id: 'A', state: 'succeeded'});
  await Promise.resolve(); await Promise.resolve();
  state.capture = {id: 'capture-B'};
  state.activePoll = 'job-B'; state.busy = true;
  refresh.resolve({id: 'capture-A', stale: true});
  await first;
  assert.equal(state.capture.id, 'capture-B');
  assert.equal(state.busy, true);
  assert.equal(state.activePoll, 'job-B');
});


test('an upload without sessions clears the previous inspector and selection', async () => {
  const {context, state, element} = controller();
  state.selected = 'old'; state.exchange = {index: 1}; state.job = {id: 'old-job'};
  context.api = async () => ({id: 'empty', sessions: []});
  await context.upload({name: 'udp-only.pcap'});
  assert.equal(state.selected, null); assert.equal(state.exchange, null); assert.equal(state.job, null);
  for (const id of ['#session-detail', '#inspector', '#job-panel']) assert.equal(element(id).hidden, true);
});
