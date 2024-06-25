/* tslint:disable */
/* eslint-disable */
/**
* @param {string} private_key_pem
* @returns {ProofKey}
*/
export function createProofKey(private_key_pem: string): ProofKey;
/**
* @param {string} application
* @param {ProofKey} key
* @param {string} user_id
* @returns {string}
*/
export function createResetProof(application: string, key: ProofKey, user_id: string): string;
/**
* @param {string} application
* @param {ProofKey} key
* @returns {string}
*/
export function createReadAllProof(application: string, key: ProofKey): string;
/**
*/
export class ProofKey {
  free(): void;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly __wbg_proofkey_free: (a: number) => void;
  readonly createProofKey: (a: number, b: number, c: number) => void;
  readonly createResetProof: (a: number, b: number, c: number, d: number, e: number, f: number) => void;
  readonly createReadAllProof: (a: number, b: number, c: number, d: number) => void;
  readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_exn_store: (a: number) => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {SyncInitInput} module
*
* @returns {InitOutput}
*/
export function initSync(module: SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {InitInput | Promise<InitInput>} module_or_path
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: InitInput | Promise<InitInput>): Promise<InitOutput>;
