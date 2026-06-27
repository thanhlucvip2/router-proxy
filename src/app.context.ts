import { RuntimeOptions } from './types';

export class AppContext {
  options!: RuntimeOptions;
  adminPassword = '';
  sessionToken = '';
}
