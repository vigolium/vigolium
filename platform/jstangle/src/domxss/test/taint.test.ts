import { describe, expect, test } from 'vitest';
import { jstangle } from '../../index';

async function flows(code: string) {
  const result = await jstangle(code);
  return result.domFlows;
}

describe('dom-xss taint', () => {
  test('detects location.hash -> innerHTML', async () => {
    const f = await flows(
      `var x = location.hash; document.getElementById('a').innerHTML = x;`,
    );
    expect(f).toHaveLength(1);
    expect(f[0].source).toBe('location.hash');
    expect(f[0].sink).toBe('innerHTML');
  });

  test('propagates through decodeURIComponent into eval', async () => {
    const f = await flows(`eval(decodeURIComponent(location.search));`);
    expect(f).toHaveLength(1);
    expect(f[0].sink).toBe('eval');
    expect(f[0].source).toBe('location.search');
  });

  test('propagates across a chain of assignments', async () => {
    const f = await flows(
      `var a = location.search; var b = a.substring(1); var c = b; el.outerHTML = c;`,
    );
    expect(f).toHaveLength(1);
    expect(f[0].sink).toBe('outerHTML');
  });

  test('no flow when sink uses a constant (the key win over regex)', async () => {
    // Both a source read and a sink exist, but they are not connected.
    const f = await flows(
      `var x = location.hash; el.innerHTML = "<b>static</b>";`,
    );
    expect(f).toHaveLength(0);
  });

  test('no flow for a source with no sink', async () => {
    const f = await flows(`var x = location.hash; console.log(x);`);
    expect(f).toHaveLength(0);
  });

  test('no flow for a sink with no source', async () => {
    const f = await flows(`el.innerHTML = someServerValue;`);
    expect(f).toHaveLength(0);
  });

  test('detects document.cookie -> document.write', async () => {
    const f = await flows(`document.write("Hi " + document.cookie);`);
    expect(f).toHaveLength(1);
    expect(f[0].sink).toBe('document.write');
    expect(f[0].source).toBe('document.cookie');
  });

  test('setTimeout with a tainted string is a sink, with a function is not', async () => {
    const sink = await flows(`var p = location.hash; setTimeout(p, 100);`);
    expect(sink).toHaveLength(1);
    expect(sink[0].sink).toBe('setTimeout');

    const noSink = await flows(
      `var p = location.hash; setTimeout(function(){ console.log(p); }, 100);`,
    );
    expect(noSink).toHaveLength(0);
  });

  test('does not use assignments that occur after the sink', async () => {
    const f = await flows(`let value; el.innerHTML = value; value = location.hash;`);
    expect(f).toHaveLength(0);
  });

  test('keeps same-named bindings in separate scopes isolated', async () => {
    const f = await flows(`
      function sourceOnly() { const value = location.hash; console.log(value); }
      function sinkOnly() { const value = 'safe'; el.innerHTML = value; }
    `);
    expect(f).toHaveLength(0);
  });

  test('does not treat shadowed browser globals as sources', async () => {
    const f = await flows(`
      function render(location, document) {
        const value = location.hash;
        document.body.innerHTML = value;
      }
      render({hash: 'safe'}, {body: document.body});
    `);
    expect(f).toHaveLength(0);
  });

  test('an unconditional clean write kills earlier taint', async () => {
    const f = await flows(`let value = location.hash; value = 'safe'; el.innerHTML = value;`);
    expect(f).toHaveLength(0);
  });

  test('summarizes local return values across calls', async () => {
    const f = await flows(`
      function readHash() { return decodeURIComponent(location.hash); }
      const value = readHash();
      el.innerHTML = value;
    `);
    expect(f).toHaveLength(1);
    expect(f[0].path.some((entry) => entry.kind === 'return')).toBe(true);
  });

  test('replays sink summaries with concrete call-site arguments', async () => {
    const f = await flows(`
      function render(value) { document.body.innerHTML = value; }
      render(location.search);
    `);
    expect(f).toHaveLength(1);
    expect(f[0].source).toBe('location.search');
  });

  test('recognizes strong sanitizer barriers', async () => {
    const f = await flows(`
      const value = DOMPurify.sanitize(location.hash);
      document.body.innerHTML = value;
    `);
    expect(f).toHaveLength(0);
  });

  test('models postMessage event data as a medium-confidence source', async () => {
    const f = await flows(`
      window.addEventListener('message', (event) => {
        document.body.innerHTML = event.data;
      });
    `);
    expect(f).toHaveLength(1);
    expect(f[0].source).toBe('postMessage.data');
    expect(f[0].confidence).toBe('medium');
  });

  test('lowers postMessage confidence when a concrete origin check exists', async () => {
    const f = await flows(`
      window.addEventListener('message', (event) => {
        if (event.origin !== 'https://trusted.example') return;
        document.body.innerHTML = event.data;
      });
    `);
    expect(f).toHaveLength(1);
    expect(f[0].confidence).toBe('low');
    expect(f[0].path[0].label).toContain('origin checked');
  });

  test('covers framework and parser HTML sinks', async () => {
    const f = await flows(`
      const value = location.hash;
      new DOMParser().parseFromString(value, 'text/html');
      $('<div>').append(value);
      const view = <div dangerouslySetInnerHTML={{__html: value}} />;
    `);
    expect(f.map((flow) => flow.sink)).toEqual(expect.arrayContaining([
      'DOMParser.parseFromString(text/html)', 'jquery.append', 'React.dangerouslySetInnerHTML',
    ]));
  });

  test('classifies browser network/script URL flows separately', async () => {
    const f = await flows(`
      const target = location.hash;
      const xhr = new XMLHttpRequest();
      xhr.open('GET', target);
      new WebSocket(target);
      import(target);
    `);
    expect(f).toEqual(expect.arrayContaining([
      expect.objectContaining({ sink: 'XMLHttpRequest.open', flowType: 'clientRequestInjection' }),
      expect.objectContaining({ sink: 'WebSocket.url', flowType: 'clientRequestInjection' }),
      expect.objectContaining({ sink: 'dynamic import', flowType: 'scriptUrlInjection' }),
    ]));
  });

  test('emits narrowly scoped prototype-pollution evidence', async () => {
    const f = await flows(`Object.prototype[location.hash] = true;`);
    expect(f).toEqual([
      expect.objectContaining({ flowType: 'prototypePollution', sink: 'Object.prototype[dynamicKey]' }),
    ]);
  });

  test('honours the configured flow-count budget', async () => {
    const result = await jstangle(`
      a.innerHTML = location.hash;
      b.innerHTML = location.search;
      c.innerHTML = location.href;
    `, { profile: 'dom-security', limits: { maxDomFlows: 2 } });
    expect(result.domFlows).toHaveLength(2);
  });
});
