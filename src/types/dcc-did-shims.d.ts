declare module '@digitalcredentials/did-method-key' {
  export function driver(): {
    method: string;
    use: (opts: {
      multibaseMultikeyHeader: string;
      // Accept any key-suite `from` deserializer (e.g. the typed
      // `Ed25519VerificationKey.from` from `@interop/ed25519-verification-key`).
      fromMultibase: (...args: never[]) => unknown;
    }) => void;
    get: (opts: { did?: string; url?: string }) => Promise<unknown>;
  };
}

declare module '@digitalcredentials/did-io' {
  export class CachedResolver {
    constructor(opts?: { max?: number; maxAge?: number });

    use: (driver: unknown) => void;

    get: (opts: { did?: string; url?: string }) => Promise<unknown>;
  }
}
