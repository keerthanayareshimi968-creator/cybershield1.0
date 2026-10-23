import express from 'express';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import apiRouter from './routes/api.js';
import { getDatabase } from './database/db.js';
import { initializeKeys } from './security/crypto.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '../../');

async function startServer() {
  const app = express();
  const port = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;

  // Middleware
  app.use(express.json({ limit: '15mb' }));
  app.use(express.urlencoded({ extended: true, limit: '15mb' }));

  // Initialize DB and Cryptographic Keystore
  try {
    await getDatabase();
    await initializeKeys();
    console.log('[IoT CyberShield] SQLite Database & Ed25519 Keystore initialized.');
  } catch (err) {
    console.error('[IoT CyberShield] Initialization error:', err);
  }

  // Mount API router
  app.use('/api', apiRouter);

  // Serve static assets from /public if any
  const publicDir = path.join(rootDir, 'public');
  if (fs.existsSync(publicDir)) {
    app.use('/public', express.static(publicDir));
  }

  const isProduction = process.env.NODE_ENV === 'production' || process.env.BUILD_MODE === 'true';
  const distDir = path.join(rootDir, 'dist');

  if (!isProduction && fs.existsSync(path.join(rootDir, 'vite.config.ts'))) {
    console.log('[IoT CyberShield] Attaching Vite development middleware...');
    try {
      const { createServer: createViteServer } = await import('vite');
      const vite = await createViteServer({
        root: rootDir,
        server: {
          middlewareMode: true,
          host: '0.0.0.0',
          port,
        },
        appType: 'spa',
      });
      app.use(vite.middlewares);
    } catch (err) {
      console.warn('[IoT CyberShield] Vite middleware initialization fallback:', err);
      if (fs.existsSync(distDir)) {
        app.use(express.static(distDir));
        app.get('*', (_req, res) => res.sendFile(path.join(distDir, 'index.html')));
      }
    }
  } else if (fs.existsSync(distDir)) {
    console.log('[IoT CyberShield] Serving built frontend from /dist...');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => res.sendFile(path.join(distDir, 'index.html')));
  } else {
    app.get('/', (_req, res) => {
      res.send(`
        <html>
          <body style="background:#0b0f19;color:#00f2fe;font-family:sans-serif;padding:40px;text-align:center;">
            <h1>IoT CyberShield Server Ready</h1>
            <p>API is active. Build frontend with <code>npm run build</code> or run in development mode.</p>
          </body>
        </html>
      `);
    });
  }

  app.listen(port, '0.0.0.0', () => {
    console.log(`[IoT CyberShield] Security Server running at http://0.0.0.0:${port}`);
  });
}

startServer().catch(err => {
  console.error('[IoT CyberShield] Fatal server error:', err);
  process.exit(1);
});
