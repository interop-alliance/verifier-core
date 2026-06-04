import { z } from 'zod';

export const IssuerObjectSchema = z
  .object({
    id: z.string(),
    type: z.union([z.string(), z.array(z.string())]).optional(),
    name: z.string().optional(),
    url: z.string().optional(),
    image: z
      .union([z.string(), z.object({ id: z.string(), type: z.string() })])
      .optional()
  })
  .passthrough();

export const IssuerSchema = z.union([z.string(), IssuerObjectSchema]);
export type Issuer = z.infer<typeof IssuerSchema>;
