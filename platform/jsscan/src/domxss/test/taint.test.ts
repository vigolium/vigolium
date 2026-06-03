import { describe, expect, test } from 'vitest';
import { jsscan } from '../../index';

async function flows(code: string) {
  const result = await jsscan(code);
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
});
