const isDevelopment = process.env.NODE_ENV !== 'production';

type LogArgs = unknown[];

export const logger = {
  log: (...args: LogArgs) => {
    if (isDevelopment) console.warn(...args);
  },
  warn: (...args: LogArgs) => {
    if (isDevelopment) console.warn(...args);
  },
  error: (...args: LogArgs) => {
    // Always log errors, but avoid noisy objects in prod
    if (isDevelopment) {
      console.error(...args);
    } else {
      // Only print messages/strings in production
      const filtered = args.filter(a => typeof a === 'string');
      if (filtered.length) console.error(...filtered);
    }
  },
};

export default logger;


