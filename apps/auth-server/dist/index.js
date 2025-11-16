"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
require("dotenv/config");
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const auth_1 = require("./routes/auth");
const app = (0, express_1.default)();
app.use((0, cors_1.default)({
    origin: ['http://localhost:3000', 'http://127.0.0.1:3000'],
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    optionsSuccessStatus: 200,
}));
app.options('*', (0, cors_1.default)());
app.use(express_1.default.json());
app.get('/health', (_req, res) => res.json({ ok: true }));
// Mount under both to be safe
app.use('/auth', auth_1.authRouter);
app.use('/api/auth', auth_1.authRouter);
// remove any top-level fetch/await demo code here — it triggers TLA errors
const port = process.env.PORT ? Number(process.env.PORT) : 4000;
const host = '0.0.0.0';
app.listen(port, host, () => {
    console.log(`auth-server listening on http://${host}:${port}`);
});
