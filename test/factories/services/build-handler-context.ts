import type { RegistryHandlerContext } from '../../../src/services/registry-handlers/types.js';
import { FakeTimeService } from '../../../src/services/time-service/fake-time-service.js';
import { FakeCacheService } from './fake-cache-service.js';
import { FakeHttpGetService } from './fake-http-get-service.js';
import { FakeVerifier } from './fake-verifier.js';

/** Build a {@link RegistryHandlerContext} of fakes for handler unit tests. */
export function buildHandlerContext(
  overrides: Partial<RegistryHandlerContext> = {}
): RegistryHandlerContext {
  return {
    httpGetService: overrides.httpGetService ?? FakeHttpGetService({}),
    cacheService: overrides.cacheService ?? FakeCacheService(),
    timeService: overrides.timeService ?? FakeTimeService(),
    verifier: overrides.verifier ?? FakeVerifier()
  };
}
