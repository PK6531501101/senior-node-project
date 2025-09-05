// ==== Imports ====
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// ==== Config ====
const app = express();
const PORT = 3000;
const SECRET = "mysecretkey";
const uploadDir = path.join(__dirname, 'uploads/complaints');

// ==== Middleware ====
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ==== MongoDB ====
mongoose.connect('mongodb://127.0.0.1:27017/VOC')
    .then(() => console.log("MongoDB connected"))
    .catch(console.log);

// ==== File Upload ====
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
const storage = multer.diskStorage({
    destination: (_, __, cb) => cb(null, uploadDir),
    filename: (_, file, cb) => cb(null, Date.now() + '-' + Math.round(Math.random() * 1e9) + path.extname(file.originalname))
});
const upload = multer({ storage });

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ==== Models ====
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    phone: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: Number, default: 1 },
    division: { type: String, default: "General Public" }
});
const User = mongoose.model('User', userSchema);

// ==== Auth Middleware ====
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided' });

    jwt.verify(token, SECRET, (err, user) =>
        err ? res.status(403).json({ error: 'Invalid token' }) : (req.user = user, next())
    );
};
const checkRole = (req, res, next) => {
    if (![2, 3].includes(req.user.role)) return res.status(403).json({ error: 'Access denied' });
    next();
};

// ==== Routes ====

// Register
app.post('/register', async (req, res) => {
    try {
        const { username, email, password, name, phone, role, division } = req.body;
        if (await User.findOne({ $or: [{ username }, { email }] }))
            return res.status(400).json({ error: "Username or Email already exists" });

        const hashedPassword = await bcrypt.hash(password, 10);
        await User.create({ username, email, name, phone, password: hashedPassword, role: role || 1, division });
        res.json({ message: "User registered successfully" });
    } catch {
        res.status(500).json({ error: "Registration failed" });
    }
});

// Login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ error: "User not found" });
    if (!await bcrypt.compare(password, user.password)) return res.status(400).json({ error: "Invalid password" });

    const token = jwt.sign(
        { id: user._id, username, email: user.email, role: user.role, division: user.division },
        SECRET, { expiresIn: '1h' }
    );

    res.json({
        message: "Login successful",
        token,
        user: { id: user._id, username, name: user.name, email: user.email, phone: user.phone, role: user.role, division: user.division }
    });
});

// Profile
app.get('/profile', authenticateToken, async (req, res) => {
    const user = await User.findById(req.user.id).select('-password');
    user ? res.json(user) : res.status(404).json({ error: 'User not found' });
});

// My Reports 
app.get('/myreports', authenticateToken, async (req, res) => {
    try {
        const email = req.user.email;
        const complaints = await Complaint.find({ email });
        const corruptions = await Corruption.find({ email });

        // update view ถ้ามี message/predict ใหม่
        for (let c of complaints) {
            if ((c.acceptInfo?.message && c.acceptInfo.message.trim() !== '') ||
                (c.acceptInfo?.predict && c.acceptInfo.predict.trim() !== '')) {
                if (c.view !== 'Not read yet') {
                    c.view = 'Not read yet';
                    await c.save();
                }
            }
        }

        for (let c of corruptions) {
            if ((c.acceptInfo?.message && c.acceptInfo.message.trim() !== '') ||
                (c.acceptInfo?.predict && c.acceptInfo.predict.trim() !== '')) {
                if (c.view !== 'Not read yet') {
                    c.view = 'Not read yet';
                    await c.save();
                }
            }
        }

        const reports = [
            ...complaints.map(c => ({
                _id: c._id,
                type: 'Complaint',
                title: c.title,
                status: c.status,
                acceptInfo: c.acceptInfo,
                date: c.date,
                view: c.view
            })),
            ...corruptions.map(c => ({
                _id: c._id,
                type: 'Corruption',
                title: c.reportedName,
                status: c.status,
                acceptInfo: c.acceptInfo,
                date: c.dateSubmitted,
                view: c.view
            }))
        ].sort((a, b) => new Date(b.date) - new Date(a.date));

        res.json(reports);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch reports' });
    }
});

// PATCH: update view field for user
app.patch('/report/:type/:id/view', authenticateToken, async (req, res) => {
    try {
        const { type, id } = req.params;
        const email = req.user.email;
        let model = type === 'Complaint' ? Complaint : Corruption;

        const report = await model.findOne({ _id: id, email });
        if (!report) return res.status(404).json({ error: 'Report not found' });

        // update view -> Read
        if (report.view === 'Not read yet') {
            report.view = 'Read';
            await report.save();
        }

        res.json({ message: `${type} marked as viewed`, report });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to update report view' });
    }
});

// new API for getting unread notifications count for Role 1
app.get('/api/unread-count', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 1) { // Check if the user's role is not 1
            return res.status(403).json({ error: 'Access denied.' });
        }

        const email = req.user.email;

        const unreadComplaintCount = await Complaint.countDocuments({ email: email, view: 'Not read yet' });
        const unreadCorruptionCount = await Corruption.countDocuments({ email: email, view: 'Not read yet' });

        const unreadCount = unreadComplaintCount + unreadCorruptionCount;

        res.json({ unreadCount });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch unread count' });
    }
});

// Unread Counts
app.get('/unread-counts', authenticateToken, async (req, res) => {
    try {
        let [suggestionCount, complaintCount, corruptionCount] = [0, 0, 0];

        // Suggestion
        if ([2, 3].includes(req.user.role)) {
            suggestionCount = await Suggestion.countDocuments({ division: req.user.division, status: 'Not read yet' });
        }

        // Complaint
        if (req.user.role === 3 || req.user.division === "Correspondence, Document, and Legal Affairs Division") {
            complaintCount = await Complaint.countDocuments({ status: 'Not read yet' });
        } else if (req.user.role === 2) {
            const complaints = await Complaint.find({ forwardHistory: { $exists: true, $ne: [] } });
            complaintCount = complaints.filter(c =>
                c.forwardHistory.some(f => f.toDivision === req.user.division && f.forwardStatus === 'Not read yet')
            ).length;
        }

        // Corruption
        if (req.user.role === 3 || req.user.division === "Correspondence, Document, and Legal Affairs Division") {
            corruptionCount = await Corruption.countDocuments({ status: 'Not read yet' });
        }

        res.json({ suggestion: suggestionCount, complaint: complaintCount, corruption: corruptionCount });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch counts' });
    }
});

// ========== ========== ========== ========== ========== ==========

// Division schema
const divisionSchema = new mongoose.Schema({
    name: { type: String, required: true },
    type: {
        type: String,
        enum: [
            'School',
            'Centre',
            'Academic Office',
            'Central Administrative Office',
            'University Council Office',
            'Property and Asset Management Office',
            'Special Unit',
            'Project / Project on Establishment',
            'Academic Service Unit',
            'Other Unit'
        ],
        required: true
    },
    email: { type: String },
    telephone: { type: String }
});
const Division = mongoose.model('Division', divisionSchema);

// Division
app.get('/divisions', async (req, res) => {
    try {
        const divisions = await Division.find();
        res.json(divisions);
    } catch {
        res.status(500).json({ error: 'Failed to fetch divisions' });
    }
});

// ========== ========== ========== ========== ========== ==========

// Suggestion schema
const suggestionSchema = new mongoose.Schema({
    date: { type: Date, default: Date.now },
    type: { type: String, required: true },
    division: { type: String, required: true },
    name: String,
    email: String,
    phone: String,
    currentStatus: { type: String, required: true },
    title: String,
    details: { type: String, required: true },
    status: { type: String, default: 'Not read yet' }
});
const Suggestion = mongoose.model('Suggestion', suggestionSchema);

// Get suggestions for user's division
app.get('/suggestions/mydivision', authenticateToken, checkRole, async (req, res) => {
    const suggestions = await Suggestion.find({ division: req.user.division });
    res.json(suggestions);
});

// Get suggestion by ID (division check)
app.get('/suggestion/:id', authenticateToken, checkRole, async (req, res) => {
    const suggestion = await Suggestion.findById(req.params.id);
    if (!suggestion) return res.status(404).json({ error: 'Suggestion not found' });
    if (suggestion.division !== req.user.division) return res.status(403).json({ error: 'Access denied for this division' });
    res.json(suggestion);
});

// Create new suggestion
app.post('/suggestion', async (req, res) => {
    try {
        const suggestion = new Suggestion(req.body);
        await suggestion.save();
        res.json({ message: 'Suggestion saved successfully' });
    } catch {
        res.status(500).json({ error: 'Failed to save suggestion' });
    }
});

// Update suggestion status to "Accept"
app.patch('/suggestion/:id/status', authenticateToken, checkRole, async (req, res) => {
    const suggestion = await Suggestion.findByIdAndUpdate(req.params.id, { status: 'Accept' }, { new: true });
    if (!suggestion) return res.status(404).json({ error: 'Suggestion not found' });
    res.json({ message: 'Status updated', suggestion });
});

// Update suggestion status to "Accept"
app.patch('/suggestion/:id/status', authenticateToken, checkRole, async (req, res) => {
    try {
        const suggestion = await Suggestion.findById(req.params.id);
        if (!suggestion) return res.status(404).json({ error: 'Suggestion not found' });
        if (suggestion.division !== req.user.division) return res.status(403).json({ error: 'Access denied for this division' });

        suggestion.status = 'Accept';
        await suggestion.save();

        res.json({ message: 'Status updated to Accept', suggestion });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to update status' });
    }
});

// Update suggestion status to "On process"
app.patch('/suggestion/:id/view', authenticateToken, checkRole, async (req, res) => {
    try {
        const suggestion = await Suggestion.findById(req.params.id);
        if (!suggestion) return res.status(404).json({ error: 'Suggestion not found' });
        if (suggestion.division !== req.user.division) return res.status(403).json({ error: 'Access denied for this division' });

        if (suggestion.status === 'Not read yet') {
            suggestion.status = 'On process';
            await suggestion.save();
        }

        res.json({ message: 'Status updated to On process', suggestion });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to update status' });
    }
});

// ========== ========== ========== ========== ========== ==========

// Complaint schema
const complaintSchema = new mongoose.Schema({
    date: { type: Date, default: Date.now },
    type: { type: String, default: "Complaint" },
    division: { type: String, required: true },
    send: { type: String, default: "Correspondence, Document, and Legal Affairs Division" },
    name: String,
    email: String,
    phone: String,
    currentStatus: { type: String, required: true },
    title: String,
    details: { type: String, required: true },
    status: { type: String, default: "Not read yet" },
    view: { type: String, default: "Not read yet" },
    file: String,
    forwardHistory: [
        {
            toDivision: String,
            fromUserId: mongoose.Schema.Types.ObjectId,
            fromUserName: String,
            forwardFile: String,
            forwardDate: { type: Date, default: Date.now },
            replyFile: String,
            replyDate: Date,
            finished: { type: Boolean, default: false },
            finishDate: Date,
            forwardStatus: { type: String, default: "Not read yet" }
        }
    ],
    acceptInfo: {
        predict: String,
        acceptedBy: String,
        message: String,
        acceptedDate: Date,
        finished: { type: Boolean, default: false },
        finishDate: Date
    },
    expectedFinishDate: Date,
});
const Complaint = mongoose.model('Complaint', complaintSchema);

// Create complaint
app.post('/complaint', upload.single('file'), async (req, res) => {
    try {
        const complaint = new Complaint({ ...req.body, file: req.file?.filename });
        await complaint.save();
        res.json({ message: 'Complaint saved successfully' });
    } catch {
        res.status(500).json({ error: 'Failed to save complaint' });
    }
});

// Get all complaint
app.get('/complaints', authenticateToken, checkRole, async (req, res) => {
    const complaints = await Complaint.find({
        $or: [
            { send: "Correspondence, Document, and Legal Affairs Division" },
            { "forwardHistory.fromUserName": "Legal" }
        ]
    }).select('title status send forwardHistory date');
    res.json(complaints);
});

// Get complaint by ID
app.get('/complaint/:id', authenticateToken, checkRole, async (req, res) => {
    const complaint = await Complaint.findById(req.params.id);
    if (!complaint) return res.status(404).json({ error: 'Complaint not found' });
    res.json(complaint);
});

// Forward complaint
app.post('/complaint/forward/:id', authenticateToken, checkRole, upload.single('forwardFile'), async (req, res) => {
    try {
        const complaint = await Complaint.findById(req.params.id);
        if (!complaint) return res.status(404).json({ error: 'Complaint not found' });

        // เพิ่ม forwardHistory
        complaint.forwardHistory.push({
            toDivision: req.body.toDivision,
            fromUserId: req.user.id,
            fromUserName: req.user.username,
            forwardFile: req.file?.filename,
            forwardDate: new Date(),
            finished: false,
            forwardStatus: "Not read yet"
        });

        // เปลี่ยน status เป็น Forward หลังจาก forward
        complaint.status = 'Forward';

        await complaint.save();
        res.json({ message: 'Forward saved and status updated to Forward', complaint });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to forward complaint' });
    }
});

// Reply forward file
app.post('/complaint/forward/reply/:complaintId/:forwardId', authenticateToken, checkRole, upload.single('replyFile'), async (req, res) => {
    const complaint = await Complaint.findById(req.params.complaintId);
    if (!complaint) return res.status(404).json({ error: 'Complaint not found' });

    const forward = complaint.forwardHistory.id(req.params.forwardId);
    if (!forward) return res.status(404).json({ error: 'Forward record not found' });

    forward.replyFile = req.file?.filename;
    forward.replyDate = new Date();
    forward.forwardStatus = "Finished";
    await complaint.save();

    res.json({ message: 'Reply file uploaded' });
});

// Accept complaint
app.post('/complaint/accept/:id', authenticateToken, checkRole, async (req, res) => {
    const complaint = await Complaint.findById(req.params.id);
    if (!complaint) return res.status(404).json({ error: 'Complaint not found' });

    complaint.acceptInfo = { ...req.body, acceptedDate: new Date(), finished: false };
    complaint.status = 'Accept';
    await complaint.save();
    res.json({ message: 'Accept info saved' });
});

// Finish complaint
app.post('/complaint/finish/:id', authenticateToken, checkRole, async (req, res) => {
    const complaint = await Complaint.findById(req.params.id);
    if (!complaint) return res.status(404).json({ error: 'Complaint not found' });

    // Mark last forward as finished
    const lastForward = complaint.forwardHistory.slice(-1)[0];
    if (lastForward) {
        lastForward.finished = true;
        lastForward.finishDate = new Date();
    }

    // Mark acceptInfo as finished
    if (complaint.acceptInfo?.acceptedDate) {
        complaint.acceptInfo.finished = true;
        complaint.acceptInfo.finishDate = new Date();
    }

    complaint.status = 'Finished';
    await complaint.save();
    res.json({ message: 'Complaint marked as finished' });
});

// Update complaint status to "On Process" when viewed
app.patch('/complaint/:id/view', authenticateToken, checkRole, async (req, res) => {
    try {
        const complaint = await Complaint.findById(req.params.id);
        if (!complaint) return res.status(404).json({ error: 'Complaint not found' });

        if (complaint.status === 'Not read yet') {
            complaint.status = 'On Process';
            await complaint.save();
        }

        res.json({ message: 'Status updated to On Process', complaint });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to update complaint status' });
    }
});

// PATCH /complaint/forward/view/:complaintId/:forwardId
app.patch('/complaint/forward/view/:complaintId/:forwardId', authenticateToken, checkRole, async (req, res) => {
    try {
        const complaint = await Complaint.findById(req.params.complaintId);
        if (!complaint) return res.status(404).json({ error: 'Complaint not found' });

        const forward = complaint.forwardHistory.id(req.params.forwardId);
        if (!forward) return res.status(404).json({ error: 'Forward record not found' });

        // อัปเดต status เป็น On process ถ้ายังไม่ดู
        if (forward.forwardStatus === "Not read yet") {
            forward.forwardStatus = "On process";
            await complaint.save();
        }

        res.json({ message: 'Forward status updated to On process', forward });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to update forward status' });
    }
});

// Cancel latest forward
app.post('/complaint/cancel-forward/:id', authenticateToken, checkRole, async (req, res) => {
    try {
        const complaint = await Complaint.findById(req.params.id);
        if (!complaint) return res.status(404).json({ error: 'Complaint not found' });

        complaint.forwardHistory = complaint.forwardHistory.filter(f => f._id.toString() !== req.body.forwardId);
        if (complaint.forwardHistory.length === 0) {
            complaint.status = 'On Process';
        }
        await complaint.save();

        res.json({ message: 'Forward canceled successfully' });
    } catch {
        res.status(500).json({ error: 'Failed to cancel forward' });
    }
});

// Cancel Accept
app.post('/complaint/cancel-accept/:id', authenticateToken, checkRole, async (req, res) => {
    try {
        const complaint = await Complaint.findById(req.params.id);
        if (!complaint) return res.status(404).json({ error: 'Complaint not found' });

        complaint.acceptInfo = null;
        complaint.status = 'On Process';
        await complaint.save();

        res.json({ message: 'Accept canceled and status reverted to On Process' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to cancel accept' });
    }
});

app.put('/complaints/:id/mark-on-process', authenticateToken, async (req, res) => {
    try {
        const complaintId = req.params.id;
        const userDivision = req.user.division;

        const complaint = await Complaint.findById(complaintId);
        if (!complaint) return res.status(404).json({ error: 'Complaint not found' });

        // อัปเดต forwardStatus เฉพาะ forwardHistory ที่ toDivision ตรงกับ user
        let updated = false;
        complaint.forwardHistory.forEach(fwd => {
            if (fwd.toDivision === userDivision && fwd.forwardStatus === 'Not read yet') {
                fwd.forwardStatus = 'On process';
                updated = true;
            }
        });

        if (updated) {
            await complaint.save();
        }

        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to update forwardStatus' });
    }
});

app.post('/complaint/accept/:id', authenticateToken, async (req, res) => {
    try {
        const complaintId = req.params.id;
        const { predict, acceptedBy, message } = req.body;
        const userDivision = req.user.division;

        const complaint = await Complaint.findById(complaintId);
        if (!complaint) return res.status(404).json({ error: 'Complaint not found' });

        // บันทึก Accept info
        complaint.acceptInfo = {
            predict,
            acceptedBy,
            message,
            acceptedDate: new Date(),
            finished: false
        };

        // อัปเดต forwardStatus ของ forwardHistory ที่ตรงกับ division และ status = 'On process'
        complaint.forwardHistory.forEach(fwd => {
            if (fwd.toDivision === userDivision && fwd.forwardStatus === 'On process') {
                fwd.forwardStatus = 'Accepting';
            }
        });

        await complaint.save();
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to accept complaint' });
    }
});

// ========== ========== ========== ========== ========== ==========

// Corruption schema
const corruptionSchema = new mongoose.Schema({
    name: { type: String, required: true },
    address: String,
    idCard: { type: String, required: true },
    phone: { type: String, required: true },
    email: { type: String, required: true },
    currentStatus: { type: String, enum: ['student', 'staff', 'alumni', 'public'], required: true },

    reportedName: { type: String, required: true },
    position: String,
    division: String,
    location: { type: String, required: true },
    dateOfIncident: { type: Date, required: true },
    description: { type: String, required: true },
    requestAction: { type: String, required: true },

    file: String,
    acceptInfo: {
        predict: String,
        acceptedBy: String,
        message: String,
        acceptedDate: Date,
        finished: { type: Boolean, default: false },
        finishDate: Date
    },

    dateSubmitted: { type: Date, default: Date.now },
    status: { type: String, default: "Not read yet" },
    view: { type: String, default: "Not read yet" },
    expectedFinishDate: Date,
    send: { type: String, default: "Correspondence, Document, and Legal Affairs Division" }
});
const Corruption = mongoose.model('Corruption', corruptionSchema);

// Create corruption
app.post('/corruption', upload.single('file'), async (req, res) => {
    try {
        const corruption = new Corruption({ ...req.body, file: req.file?.filename });
        await corruption.save();
        res.json({ message: 'Corruption report saved successfully' });
    } catch (err) {
        console.error("Error saving corruption report:", err);
        res.status(500).json({ error: 'Failed to save corruption report' });
    }
});

// Get all corruption reports (เฉพาะ role=3 หรือ division Legal)
app.get('/corruptions', authenticateToken, async (req, res) => {
    try {
        const { role, division } = req.user;

        // role 2 จะไม่เห็น corruption
        if (role !== 3 && division !== "Correspondence, Document, and Legal Affairs Division") {
            return res.status(403).json({ error: "Access denied" });
        }

        // กรองเฉพาะ send = division ของ user
        const corruptions = await Corruption.find({ send: division });
        res.json(corruptions);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to fetch corruption reports" });
    }
});

// Get corruption by ID
app.get('/corruption/:id', authenticateToken, async (req, res) => {
    const corruption = await Corruption.findById(req.params.id);
    if (!corruption) return res.status(404).json({ error: 'Corruption report not found' });

    // ตรวจสอบสิทธิ์
    if (req.user.role !== 3 && req.user.division !== corruption.send) {
        return res.status(403).json({ error: "Access denied" });
    }

    res.json(corruption);
});

// Accept corruption report
app.post('/corruption/accept/:id', authenticateToken, async (req, res) => {
    const { predict, acceptedBy, message } = req.body;
    if (!predict || !acceptedBy) return res.status(400).json({ error: 'Missing predict or acceptedBy' });

    const corruption = await Corruption.findById(req.params.id);
    if (!corruption) return res.status(404).json({ error: 'Corruption report not found' });

    if (req.user.role !== 3 && req.user.division !== corruption.send) {
        return res.status(403).json({ error: "Access denied" });
    }

    corruption.acceptInfo = { predict, acceptedBy, message, acceptedDate: new Date(), finished: false };
    corruption.status = 'On process';

    await corruption.save();
    res.json({ message: 'Accept info saved' });
});

// Finish corruption report
app.post('/corruption/finish/:id', authenticateToken, async (req, res) => {
    const corruption = await Corruption.findById(req.params.id);
    if (!corruption) return res.status(404).json({ error: 'Corruption report not found' });

    if (req.user.role !== 3 && req.user.division !== corruption.send) {
        return res.status(403).json({ error: "Access denied" });
    }

    if (corruption.acceptInfo?.acceptedDate) {
        corruption.acceptInfo.finished = true;
        corruption.acceptInfo.finishDate = new Date();
    }
    corruption.status = 'Finished';

    await corruption.save();
    res.json({ message: 'Corruption report marked as finished' });
});

// Mark corruption report as "On Process"
app.patch('/corruption/:id/view', authenticateToken, async (req, res) => {
    try {
        const corruption = await Corruption.findById(req.params.id);
        if (!corruption) return res.status(404).json({ error: 'Corruption report not found' });

        // ตรวจสอบสิทธิ์: role 3 หรือ division ตรงกัน
        if (req.user.role !== 3 && req.user.division !== corruption.send) {
            return res.status(403).json({ error: "Access denied" });
        }

        // อัปเดต status ถ้ายัง Not read yet
        if (corruption.status === 'Not read yet') {
            corruption.status = 'On Process';
            await corruption.save();
        }

        res.json({ message: 'Corruption report status updated' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to update corruption status' });
    }
});

// ========== ========== ========== ========== ========== ==========

// Evaluation schema
const evaluationSchema = new mongoose.Schema({
    title: { type: String, required: true },
    division: { type: String, required: true },
    degreeLevel: { type: String, enum: ['Bachelor', 'Master', 'Doctorate', 'Other'], required: true },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    createdAt: { type: Date, default: Date.now },
    questions: [
        {
            questionText: { type: String, required: true },
            questionType: { type: String, enum: ['text', 'multiple-choice', 'dropdown', 'rating', 'checkbox'], required: true },
            options: [String],
            required: { type: Boolean, default: false }
        }
    ],
    responses: [
        {
            userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
            answers: [
                { questionId: { type: mongoose.Schema.Types.ObjectId, required: true }, answer: mongoose.Schema.Types.Mixed }
            ],
            submittedAt: { type: Date, default: Date.now }
        }
    ]
}, { timestamps: true });
const Evaluation = mongoose.model('Evaluation', evaluationSchema);

// Get evaluations by school division
app.get('/divisions/school', async (req, res) => {
    try {
        const divisions = await Division.find({ type: 'School' });
        res.json(divisions);
    } catch {
        res.status(500).json({ error: 'Failed to fetch school divisions' });
    }
});

// Create evaluation
app.post('/evaluation', authenticateToken, async (req, res) => {
    try {
        const { title, degreeLevel, division, questions } = req.body;
        const evaluation = new Evaluation({
            title, degreeLevel, division,
            questions: questions.map(q => ({ ...q, options: q.options || [], required: q.required || false })),
            createdBy: req.user.id
        });
        await evaluation.save();
        res.json({ message: 'Evaluation created successfully', evaluation });
    } catch {
        res.status(500).json({ error: 'Failed to create evaluation' });
    }
});

// Submit evaluation response
app.post('/evaluation/:id/response', authenticateToken, async (req, res) => {
    try {
        const evaluation = await Evaluation.findById(req.params.id);
        if (!evaluation) return res.status(404).json({ error: 'Evaluation not found' });

        evaluation.responses.push({ userId: req.user.id, answers: req.body.answers });
        await evaluation.save();
        res.json({ message: 'Evaluation submitted successfully' });
    } catch {
        res.status(500).json({ error: 'Failed to submit evaluation' });
    }
});

// Update evaluation
app.put('/evaluation/:id', authenticateToken, async (req, res) => {
    try {
        const evaluation = await Evaluation.findById(req.params.id);
        if (!evaluation) return res.status(404).json({ error: 'Evaluation not found' });
        if (evaluation.createdBy.toString() !== req.user.id) return res.status(403).json({ error: 'Unauthorized' });

        const { title, degreeLevel, division, questions } = req.body;
        evaluation.title = title;
        evaluation.degreeLevel = degreeLevel;
        evaluation.division = division;
        evaluation.questions = questions.map(q => ({ ...q, options: q.options || [], required: q.required || false }));

        await evaluation.save();
        res.json({ message: 'Evaluation updated successfully', evaluation });
    } catch {
        res.status(500).json({ error: 'Failed to update evaluation' });
    }
});

// Get evaluations by division
app.get('/evaluations/division/:division', async (req, res) => {
    try {
        const regex = new RegExp(`^${req.params.division.trim()}$`, 'i');
        const evaluations = await Evaluation.find({ division: regex }).populate('createdBy', 'username email');
        if (!evaluations.length) return res.status(404).json({ error: 'No evaluations found for this division' });
        res.json(evaluations);
    } catch {
        res.status(500).json({ error: 'Failed to fetch evaluations by division' });
    }
});

// Get evaluation by ID
app.get('/evaluation/:id', authenticateToken, async (req, res) => {
    try {
        const evaluation = await Evaluation.findById(req.params.id);
        if (!evaluation) return res.status(404).json({ error: 'Evaluation not found' });
        res.json(evaluation);
    } catch {
        res.status(500).json({ error: 'Failed to fetch evaluation' });
    }
});

// ========== ========== ========== ========== ========== ==========
// Dashboard สำหรับ Role = 2 (Staff)
app.get('/dashboard/staff', authenticateToken, async (req, res) => {
    if (req.user.role !== 2) return res.status(403).json({ error: "Access denied" });

    try {
        const division = req.user.division;
        const startOfMonth = new Date(new Date().getFullYear(), new Date().getMonth(), 1);
        const endOfMonth = new Date(new Date().getFullYear(), new Date().getMonth() + 1, 0);

        const [suggestions, complaints, evaluations] = await Promise.all([
            Suggestion.find({ date: { $gte: startOfMonth, $lte: endOfMonth }, division }),
            Complaint.find({ date: { $gte: startOfMonth, $lte: endOfMonth }, "forwardHistory.toDivision": division }),
            Evaluation.find({ createdAt: { $gte: startOfMonth, $lte: endOfMonth }, division })
        ]);

        const dailyCount = {};
        for (let d = 1; d <= 31; d++)
            dailyCount[d] = { suggestion: 0, complaint: 0, corruption: 0, evaluation: 0 };

        suggestions.forEach(s => dailyCount[new Date(s.date).getDate()].suggestion++);
        complaints.forEach(c => dailyCount[new Date(c.date).getDate()].complaint++);
        evaluations.forEach(e => dailyCount[new Date(e.createdAt).getDate()].evaluation++);

        // นับจำนวน responses
        const totalResponses = evaluations.reduce((sum, e) => sum + (e.responses?.length || 0), 0);

        const total = {
            suggestion: suggestions.length,
            complaint: complaints.length,
            corruption: 0, // role=2 ไม่แสดง corruption
            evaluation: evaluations.length,
            evaluationResponses: totalResponses
        };
        const totalAll = Object.values(total).reduce((a, b) => a + b, 0);
        const pieData = Object.fromEntries(
            Object.entries(total).map(([k, v]) => [k, totalAll ? (v / totalAll * 100).toFixed(2) : 0])
        );

        const onProcessStatuses = ["On process", "Forward", "Accept", "Not read yet", "In Progress"];
        const complaintOnProcess = complaints.filter(c => onProcessStatuses.includes(c.status)).length;
        const finishedCount = complaints.filter(c => c.status === "Finished").length;

        res.json({
            lineChart: dailyCount,
            pieChart: pieData,
            boxCount: total,
            statusBox: {
                onProcess: complaintOnProcess,
                finished: finishedCount
            }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to fetch dashboard data" });
    }
});

// Dashboard สำหรับ Role = 3 & Division = Legal
app.get('/dashboard/legal', authenticateToken, async (req, res) => {
    const legalDivision = "Correspondence, Document, and Legal Affairs Division";
    if (req.user.role !== 3 || req.user.division !== legalDivision)
        return res.status(403).json({ error: "Access denied" });

    try {
        const division = req.user.division;
        const startOfMonth = new Date(new Date().getFullYear(), new Date().getMonth(), 1);
        const endOfMonth = new Date(new Date().getFullYear(), new Date().getMonth() + 1, 0);

        const [suggestions, complaints, corruptions, evaluations] = await Promise.all([
            Suggestion.find({ date: { $gte: startOfMonth, $lte: endOfMonth }, division }),
            Complaint.find({ date: { $gte: startOfMonth, $lte: endOfMonth }, send: division }),
            Corruption.find({ dateSubmitted: { $gte: startOfMonth, $lte: endOfMonth }, send: division }),
            Evaluation.find({ createdAt: { $gte: startOfMonth, $lte: endOfMonth }, division })
        ]);

        const dailyCount = {};
        for (let d = 1; d <= 31; d++)
            dailyCount[d] = { suggestion: 0, complaint: 0, corruption: 0, evaluation: 0 };

        suggestions.forEach(s => dailyCount[new Date(s.date).getDate()].suggestion++);
        complaints.forEach(c => dailyCount[new Date(c.date).getDate()].complaint++);
        corruptions.forEach(c => dailyCount[new Date(c.dateSubmitted).getDate()].corruption++);
        evaluations.forEach(e => dailyCount[new Date(e.createdAt).getDate()].evaluation++);

        // นับจำนวน responses
        const totalResponses = evaluations.reduce((sum, e) => sum + (e.responses?.length || 0), 0);

        const total = {
            suggestion: suggestions.length,
            complaint: complaints.length,
            corruption: corruptions.length,
            evaluation: evaluations.length,
            evaluationResponses: totalResponses
        };
        const totalAll = Object.values(total).reduce((a, b) => a + b, 0);
        const pieData = Object.fromEntries(
            Object.entries(total).map(([k, v]) => [k, totalAll ? (v / totalAll * 100).toFixed(2) : 0])
        );

        const onProcessStatuses = ["On process", "Forward", "Accept", "Not read yet", "In Progress"];
        const complaintOnProcess = complaints.filter(c => onProcessStatuses.includes(c.status)).length;
        const corruptionOnProcess = corruptions.filter(c => onProcessStatuses.includes(c.status)).length;
        const finishedCount = complaints.filter(c => c.status === "Finished").length +
            corruptions.filter(c => c.status === "Finished").length;

        const forwardCounts = {};

        // นับจาก Complaint
        complaints.forEach(c => {
            c.forwardHistory?.forEach(f => {
                forwardCounts[f.toDivision] = (forwardCounts[f.toDivision] || 0) + 1;
            });
        });

        // นับจาก Corruption (ถ้ามี forwardHistory เหมือนกัน)
        corruptions.forEach(c => {
            c.forwardHistory?.forEach(f => {
                forwardCounts[f.toDivision] = (forwardCounts[f.toDivision] || 0) + 1;
            });
        });

        res.json({
            lineChart: dailyCount,
            pieChart: pieData,
            boxCount: total,
            statusBox: {
                onProcess: complaintOnProcess + corruptionOnProcess,
                finished: finishedCount
            },
            barChart: forwardCounts
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to fetch dashboard data" });
    }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
