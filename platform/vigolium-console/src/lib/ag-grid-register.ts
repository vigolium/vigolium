import { AllCommunityModule, ModuleRegistry } from 'ag-grid-community';

let registered = false;

export function registerAgGrid() {
  if (!registered) {
    ModuleRegistry.registerModules([AllCommunityModule]);
    registered = true;
  }
}
