/**
 * Describe a caught value for a human-readable message. A value with a
 * string `message` (an `Error`, including one from another realm that
 * fails `instanceof`) contributes that message, a thrown string is used
 * as is, and any other value yields `fallback`. `String()` is
 * deliberately not used, since it can itself throw on exotic values.
 */
export function errorMessage(error: unknown, fallback: string): string {
  if (typeof error === 'string') {
    return error;
  }
  if (error !== null && typeof error === 'object') {
    const { message } = error as { message?: unknown };
    if (typeof message === 'string') {
      return message;
    }
  }
  return fallback;
}
