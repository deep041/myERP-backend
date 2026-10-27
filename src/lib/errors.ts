export class AppError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
    public readonly details?: { path: string; message: string }[],
  ) {
    super(message);
    this.name = 'AppError';
  }
}

export const invalidCredentials = () =>
  new AppError(401, 'INVALID_CREDENTIALS', 'Invalid email or password');

export const authenticationRequired = () =>
  new AppError(401, 'UNAUTHORIZED', 'Authentication required');
