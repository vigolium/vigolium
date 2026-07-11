import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import { afterEach, describe, expect, test } from 'vitest';
import { runWorker } from '../../worker';
import {
  encodeFrame,
  FrameProtocolError,
  FrameReader,
  writeFrame,
  type WorkerAnalyzeRequest,
  type WorkerHelloRecord,
  type WorkerResultRecord,
} from '..';

const cleanup: string[] = [];
afterEach(async () => {
  await Promise.all(cleanup.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe('length-prefixed protocol', () => {
  test('decodes multiple frames across arbitrary chunk boundaries', async () => {
    const second = new PassThrough();
    const secondReader = new FrameReader(second, 1024);
    const framed = Buffer.concat([encodeFrame({ id: 1 }), encodeFrame(Buffer.from('source'))]);
    let offset = 0;
    for (const size of [1, 2, 7, 3, framed.length]) {
      if (offset >= framed.length) break;
      second.write(framed.subarray(offset, Math.min(framed.length, offset + size)));
      offset += size;
    }
    second.end();
    await expect(secondReader.readJSON<{ id: number }>()).resolves.toEqual({ id: 1 });
    await expect(secondReader.read()).resolves.toEqual(Buffer.from('source'));
    await expect(secondReader.read()).resolves.toBeNull();
  });

  test('rejects oversized and truncated frames', async () => {
    const oversized = new PassThrough();
    const oversizedReader = new FrameReader(oversized, 4);
    const header = Buffer.alloc(4);
    header.writeUInt32BE(5);
    oversized.end(header);
    await expect(oversizedReader.read()).rejects.toBeInstanceOf(FrameProtocolError);

    const truncated = new PassThrough();
    const truncatedReader = new FrameReader(truncated, 20);
    const partial = Buffer.alloc(6);
    partial.writeUInt32BE(5);
    partial.write('xx', 4);
    truncated.end(partial);
    await expect(truncatedReader.read()).rejects.toThrow(/truncated frame payload/);
  });

  test('worker reuses one process for sequential isolated jobs', async () => {
    const artifactDir = await mkdtemp(join(tmpdir(), 'jstangle-worker-test-'));
    cleanup.push(artifactDir);
    const input = new PassThrough();
    const output = new PassThrough();
    const responses = new FrameReader(output);
    const worker = runWorker(input, output);

    const hello = await responses.readJSON<WorkerHelloRecord>();
    expect(hello?.type).toBe('workerHello');
    const urls: string[] = [];
    for (const [id, endpoint] of [['job-alpha', '/api/alpha'], ['job-beta', '/api/beta']] as const) {
      const content = Buffer.from(`fetch('${endpoint}')`);
      const request: WorkerAnalyzeRequest = {
        type: 'analyze', id, profile: 'endpoints', artifactDir,
        sourceUrl: `https://example.test/${id}.js`, contentLength: content.length,
        limits: { maxOutputBytes: 1024 * 1024 },
      };
      await writeFrame(input, request);
      await writeFrame(input, content);
      const response = await responses.readJSON<WorkerResultRecord>();
      expect(response?.id).toBe(id);
      expect(response?.completion.status).toBe('complete');
      const fact = response?.result?.records.find((record) => record.kind === 'httpRequest');
      if (fact?.kind === 'httpRequest') urls.push(fact.url.rendered);
    }
    await writeFrame(input, { type: 'shutdown' });
    await worker;
    expect(urls).toEqual(['/api/alpha', '/api/beta']);
  });
});
