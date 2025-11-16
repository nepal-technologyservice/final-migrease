import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { authRouter } from './routes/auth';

const app = express();

app.use(
  cors({
    origin: ['http://localhost:3000', 'http://127.0.0.1:3000'],
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    optionsSuccessStatus: 200,
  }),
);
app.options('*', cors());

app.use(express.json());

app.get('/health', (_req, res) => res.json({ ok: true }));

// Mount under both to be safe
app.use('/auth', authRouter);
app.use('/api/auth', authRouter);

const PORT = process.env.PORT || 4000;
app.listen(PORT, () =>
  console.log(`auth-server listening on http://localhost:${PORT}`),
);