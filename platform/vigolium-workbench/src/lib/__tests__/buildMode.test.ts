import { describe, it, expect } from 'vitest';
import { BUILD_MODE, isStaticBuild, isCloudBuild, isSkipAuth } from '../buildMode';

describe('buildMode (workbench)', () => {
  it('is locked to static', () => {
    expect(BUILD_MODE).toBe('static');
    expect(isStaticBuild).toBe(true);
    expect(isCloudBuild).toBe(false);
  });

  it('isSkipAuth always false', () => {
    expect(isSkipAuth()).toBe(false);
  });
});
