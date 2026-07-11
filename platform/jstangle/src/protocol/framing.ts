import type { Readable, Writable } from 'node:stream';

export const DEFAULT_MAX_FRAME_BYTES = 32 * 1024 * 1024;

export class FrameProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'FrameProtocolError';
  }
}

/** Reads four-byte big-endian length-prefixed frames from arbitrarily chunked input. */
export class FrameReader {
  private buffer = Buffer.alloc(0);
  private readonly iterator: AsyncIterator<Buffer | string>;

  constructor(readable: Readable, readonly maxFrameBytes = DEFAULT_MAX_FRAME_BYTES) {
    this.iterator = readable[Symbol.asyncIterator]();
  }

  async read(): Promise<Buffer | null> {
    const hasHeader = await this.fill(4);
    if (!hasHeader) {
      if (this.buffer.length !== 0) throw new FrameProtocolError('truncated frame header');
      return null;
    }
    const length = this.buffer.readUInt32BE(0);
    this.buffer = this.buffer.subarray(4);
    if (length === 0) throw new FrameProtocolError('zero-length frame');
    if (length > this.maxFrameBytes) {
      throw new FrameProtocolError(`frame length ${length} exceeds limit ${this.maxFrameBytes}`);
    }
    if (!(await this.fill(length))) {
      throw new FrameProtocolError(`truncated frame payload: wanted ${length}, received ${this.buffer.length}`);
    }
    const frame = Buffer.from(this.buffer.subarray(0, length));
    this.buffer = this.buffer.subarray(length);
    return frame;
  }

  async readJSON<T>(): Promise<T | null> {
    const frame = await this.read();
    if (frame === null) return null;
    try {
      return JSON.parse(frame.toString('utf8')) as T;
    } catch (error) {
      throw new FrameProtocolError(`invalid JSON frame: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  private async fill(length: number): Promise<boolean> {
    while (this.buffer.length < length) {
      const next = await this.iterator.next();
      if (next.done) return false;
      const chunk = typeof next.value === 'string' ? Buffer.from(next.value) : Buffer.from(next.value);
      if (chunk.length) this.buffer = this.buffer.length ? Buffer.concat([this.buffer, chunk]) : chunk;
    }
    return true;
  }
}

export function encodeFrame(value: unknown | Uint8Array): Buffer {
  const payload = value instanceof Uint8Array && !(value instanceof Buffer)
    ? Buffer.from(value)
    : Buffer.isBuffer(value)
      ? value
      : Buffer.from(JSON.stringify(value), 'utf8');
  if (payload.length === 0 || payload.length > 0xffff_ffff) {
    throw new FrameProtocolError(`invalid frame payload length: ${payload.length}`);
  }
  const header = Buffer.allocUnsafe(4);
  header.writeUInt32BE(payload.length, 0);
  return Buffer.concat([header, payload]);
}

export async function writeFrame(writable: Writable, value: unknown | Uint8Array): Promise<void> {
  const frame = encodeFrame(value);
  await new Promise<void>((resolve, reject) => {
    writable.write(frame, (error?: Error | null) => error ? reject(error) : resolve());
  });
}
