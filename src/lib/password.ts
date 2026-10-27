import argon2 from 'argon2';

const argonOptions: argon2.Options = {
  type: argon2.argon2id,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1,
};

let dummyHash: Promise<string> | undefined;

function paddingHash(): Promise<string> {
  dummyHash ??= argon2.hash('not-a-real-password', argonOptions);
  return dummyHash;
}

export function hashPassword(password: string): Promise<string> {
  return argon2.hash(password, argonOptions);
}

export async function verifyPassword(passwordHash: string | null, password: string): Promise<boolean> {
  if (!passwordHash) {
    await argon2.verify(await paddingHash(), password).catch(() => false);
    return false;
  }

  try {
    return await argon2.verify(passwordHash, password);
  } catch {
    return false;
  }
}
