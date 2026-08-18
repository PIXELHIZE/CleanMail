import { createCleanMailWorker } from './handler.js';
import { createWorkerRuntime } from './runtime.js';

export default createCleanMailWorker(createWorkerRuntime);
