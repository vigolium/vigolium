/** @jest-environment node */
/** Confirm M9: SearchStore.indexItems unbounded DoS */
const SESSION = '00000000';
const added: Array<{ title: string; meta: string }> = [];
let doneCalls = 0;

class MockWorker {
  add(title: string, _body: string, meta?: string) {
    added.push({ title, meta: meta || '' });
  }
  done() {
    doneCalls++;
  }
  terminate() {}
  dispose() {}
  search<T>() { return [] as T[]; }
  toJS() { return Promise.resolve({}); }
  load() {}
  fromExternalJS() {}
}

jest.mock('../../../src/services/SearchWorker.worker', () => ({
  __esModule: true,
  default: MockWorker,
}));

import { SearchStore } from '../../../src/services/SearchStore';

type Item = {
  type: 'group' | 'operation';
  name: string;
  description?: string;
  path?: string;
  id: string;
  items: Item[];
};

function buildAttackTree(groups: number, perGroup: number): Item[] {
  return Array.from({ length: groups }, (_, g) => ({
    type: 'group',
    name: `group-${g}`,
    id: `g-${g}`,
    items: Array.from({ length: perGroup }, (_, i) => ({
      type: 'operation',
      name: `op-${g}-${i}`,
      description: 'attacker-controlled operation',
      path: `/p-${g}-${i}`,
      id: `id-${g}-${i}`,
      items: [],
    })),
  }));
}

test(`test_confirm_searchstore_indexitems_unbounded_dos_${SESSION}`, () => {
  added.length = 0;
  doneCalls = 0;

  const attackTree = buildAttackTree(500, 100);
  const store = new SearchStore<string>();
  store.indexItems(attackTree as any);

  expect(added.length).toBe(50000);
  expect(doneCalls).toBe(1);
  expect(added[0]).toEqual({ title: 'op-0-0', meta: 'id-0-0' });
  expect(added[49999]).toEqual({ title: 'op-499-99', meta: 'id-499-99' });
});
