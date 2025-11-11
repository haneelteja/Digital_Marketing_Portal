import { NextResponse } from 'next/server';

type ErrorBody = {
  error: {
    message: string;
    details?: unknown;
    code?: string;
  };
};

export function ok<T>(data: T, init?: ResponseInit) {
  return NextResponse.json(data as unknown as Record<string, unknown>, {
    status: 200,
    ...init,
  });
}

export function created<T>(data: T) {
  return NextResponse.json(data as unknown as Record<string, unknown>, { status: 201 });
}

export function error(status: number, message: string, details?: unknown, code?: string) {
  const body: ErrorBody = { error: { message } };
  if (typeof details !== 'undefined') body.error.details = details;
  if (code) body.error.code = code;
  return NextResponse.json(body, { status });
}

export function unauthorized(message = 'Unauthorized') {
  return error(401, message);
}

export function forbidden(message = 'Forbidden') {
  return error(403, message);
}

export function notFound(message = 'Not found') {
  return error(404, message);
}

export function badRequest(message = 'Bad request', details?: unknown) {
  return error(400, message, details);
}

export function serverError(message = 'Internal server error') {
  return error(500, message);
}


