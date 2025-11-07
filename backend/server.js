require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const https = require('https');
const path = require('path');
const multer = require('multer');
const { Server } = require('socket.io');
const sequelize = require('./sequelize');
const User = require('./models/User');
const Employee = require("./models/Employee");
const LoanApplication = require("./models/LoanApplication");

const app = express();

// Middleware
app.use(express.json());
app.use(cors({
    origin: 'https://localhost:3000',
    credentials: true
}));
app.use(helmet());

const limiter = rateLimit({
    windowMs: 60 * 1000,
    max: 10,
    message: { error: 'Too many requests, please try again later.' }
});
app.use(['/api/login', '/api/signup', '/api/loans', '/api/auth/employee-login'], limiter);

const SALT_ROUNDS = parseInt(process.env.SALT_ROUNDS || '12', 10);
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';
const PORT = process.env.PORT || 5000;

// Authentication helpers
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Token required' });
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid or expired token' });
        req.user = user;
        next();
    });
}

function requireEmployee(req, res, next) {
    if (!req.user || req.user.role !== 'employee') return res.status(403).json({ error: 'Employee access only' });
    next();
}

// File uploads
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadsDir),
    filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname.replace(/\s+/g, '_'))
});
const fileFilter = (req, file, cb) => {
    if (file.mimetype === 'application/pdf') cb(null, true);
    else cb(new Error('Only PDF files are allowed'), false);
};
const upload = multer({ storage, fileFilter, limits: { fileSize: 5 * 1024 * 1024 } });

// Routes

// Signup
app.post('/api/signup', async (req, res) => {
    try {
        const { email, password } = req.body;
        const emailLower = email.toLowerCase().trim();
        const existingUser = await User.findOne({ where: { email: emailLower } });
        if (existingUser) return res.status(409).json({ error: 'User already exists' });
        const existingEmployee = await Employee.findOne({ where: { email: emailLower } });
        if (existingEmployee) return res.status(409).json({ error: 'Email already used by an employee' });
        const hash = await bcrypt.hash(password, SALT_ROUNDS);
        await User.create({ email: emailLower, passwordHash: hash });
        res.status(201).json({ message: 'User created successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Customer login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const emailLower = email.toLowerCase().trim();
        const user = await User.findOne({ where: { email: emailLower } });
        if (!user) return res.status(401).json({ error: 'Invalid credentials' });
        const match = await bcrypt.compare(password, user.passwordHash);
        if (!match) return res.status(401).json({ error: 'Invalid credentials' });
        const token = jwt.sign({ id: user.id, email: user.email, role: 'customer' }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ message: 'Login successful', token });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Employee login
app.post('/api/auth/employee-login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const emailLower = email.toLowerCase().trim();
        const employee = await Employee.findOne({ where: { email: emailLower } });
        if (!employee) return res.status(400).json({ error: 'Employee not found' });
        const isMatch = await bcrypt.compare(password, employee.passwordHash);
        if (!isMatch) return res.status(400).json({ error: 'Invalid password' });
        const token = jwt.sign({ id: employee.id, email: employee.email, role: employee.role || 'employee' }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ message: 'Employee login successful', token, role: employee.role || 'employee' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Loan routes
app.post('/api/loans', upload.single('payslip'), async (req, res) => {
    try {
        const { name, email, amount } = req.body;
        const payslipPath = req.file ? `/uploads/${req.file.filename}` : null;
        const loan = await LoanApplication.create({
            name: name.trim(),
            email: email.toLowerCase().trim(),
            amount: parseFloat(amount),
            payslipPath
        });
        io.emit('loanUpdate', { type: 'new', loan });
        res.status(201).json(loan);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to create loan application' });
    }
});

app.get('/api/loans', async (req, res) => {
    try {
        const { email } = req.query;
        const where = email ? { email: email.toLowerCase().trim() } : {};
        const loans = await LoanApplication.findAll({ where, order: [['createdAt', 'DESC']] });
        res.json(loans);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to list loan applications' });
    }
});

app.put('/api/loans/:id/status', authenticateToken, requireEmployee, async (req, res) => {
    try {
        const { status } = req.body;
        const loan = await LoanApplication.findByPk(req.params.id);
        if (!loan) return res.status(404).json({ error: 'Loan not found' });
        loan.status = status;
        await loan.save();
        io.emit('loanUpdate', { type: 'status', loan });
        res.json(loan);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to update loan status' });
    }
});

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// HTTPS server + Socket.io
const sslOptions = {
    key: fs.readFileSync(path.join(__dirname, 'certs', 'key.pem')),
    cert: fs.readFileSync(path.join(__dirname, 'certs', 'cert.pem'))
};

const httpsServer = https.createServer(sslOptions, app);
const io = new Server(httpsServer, {
    cors: { origin: 'https://localhost:3000', methods: ['GET', 'POST'], credentials: true }
});

io.on('connection', socket => {
    console.log('Socket connected:', socket.id);
    socket.on('disconnect', () => console.log('Socket disconnected:', socket.id));
});

(async () => {
    await sequelize.sync({ force: false });

    const existingEmployee = await Employee.findOne({ where: { email: 'employee@globepay.com' } });
    if (!existingEmployee) {
        const hash = await bcrypt.hash('Employee123!', SALT_ROUNDS);
        await Employee.create({ email: 'employee@globepay.com', passwordHash: hash, role: 'employee' });
        console.log('Default employee created.');
    }

    httpsServer.listen(PORT, '0.0.0.0', () => console.log(`Secure backend running at https://localhost:${PORT}`));
})();

