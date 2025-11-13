// server.js
require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');
const nodemailer = require('nodemailer');

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// PostgreSQL connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

// Middleware to authenticate token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Missing token' });
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

// Simple admin middleware
function requireAdmin(req, res, next) {
  if (req.headers['x-admin-secret'] !== process.env.ADMIN_SECRET) {
    return res.status(403).json({ error: 'Admin only' });
  }
  next();
}

/* ---------- AUTH ENDPOINTS ---------- */

// SIGNUP
app.post('/api/signup', async (req, res) => {
  try {
    const { name, email, password, hostel, year } = req.body;
    if (!name || !email || !password || !hostel || !year) {
      return res.status(400).json({ error: 'Missing fields' });
    }

    const hashed = await bcrypt.hash(password, 10);
    const q = await pool.query(
      `INSERT INTO students (name, email, password, hostel, year)
       VALUES ($1,$2,$3,$4,$5)
       RETURNING id, name, email, hostel, year`,
      [name, email, hashed, hostel, year]
    );

    const student = q.rows[0];
    const token = jwt.sign(
      { id: student.id, email: student.email },
      process.env.JWT_SECRET,
      { expiresIn: '6h' }
    );

    res.json({ message: 'Signed up and logged in', token, student });
  } catch (err) {
    if (err.code === '23505') return res.status(400).json({ error: 'Email already exists' });
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// LOGIN
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  console.log("Login attempt:", email, password);

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required" });
  }

  try {
    const result = await pool.query("SELECT * FROM students WHERE email = $1", [email]);
    if (result.rows.length === 0) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    res.json({
      success: true,
      student: {
        id: user.id,
        name: user.name,
        hostel: user.hostel,
        year: user.year,
        email: user.email,
      },
    });

  } catch (err) {
    console.error("❌ Login error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

/* ---------- STUDENT ENDPOINTS ---------- */

// Get profile
app.get('/api/me', authenticateToken, async (req, res) => {
  const q = await pool.query('SELECT id, name, email, hostel, year FROM students WHERE id=$1', [req.user.id]);
  if (q.rows.length === 0) return res.status(404).json({ error: 'Not found' });
  res.json(q.rows[0]);
});

// Apply Leave Route
app.post("/apply-leave", async (req, res) => {
  const { student_id, from_date, to_date, reason } = req.body;

  if (!student_id || !from_date || !to_date || !reason) {
    return res.status(400).json({ success: false, message: "All fields are required" });
  }

  try {
    await pool.query(
      "INSERT INTO leaves (student_id, from_date, to_date, reason, status, applied_at) VALUES ($1, $2, $3, $4, 'Pending', NOW())",
      [student_id, from_date, to_date, reason]
    );

    res.json({ success: true, message: "Leave applied successfully!" });
  } catch (err) {
    console.error("❌ Error inserting leave:", err);
    res.status(500).json({ success: false, message: "Database error" });
  }
});

/* ---------- FIXED: MY LEAVES WITH INDIAN TIME & AM/PM ---------- */
app.get('/api/my-leaves', async (req, res) => {
  try {
    const studentId = req.query.student_id;

    if (!studentId) {
      return res.status(400).json({ error: "student_id is required" });
    }

    const r = await pool.query(`
      SELECT 
        id,
        to_char(from_date AT TIME ZONE 'UTC' AT TIME ZONE 'Asia/Kolkata', 'DD Mon YYYY, HH12:MI AM') AS from_date,
        to_char(to_date AT TIME ZONE 'UTC' AT TIME ZONE 'Asia/Kolkata', 'DD Mon YYYY, HH12:MI AM') AS to_date,
        reason,
        status
      FROM leaves
      WHERE student_id = $1
      ORDER BY applied_at DESC
    `, [studentId]);

    res.json(r.rows);
  } catch (err) {
    console.error('❌ Error fetching leaves:', err);
    res.status(500).json({ error: 'Failed to load leave history' });
  }
});

/* ---------- ADMIN ENDPOINTS ---------- */

app.get('/api/leaves', requireAdmin, async (req, res) => {
  const r = await pool.query(`
    SELECT l.*, s.name, s.email, s.hostel, s.year
    FROM leaves l
    JOIN students s ON l.student_id = s.id
    ORDER BY l.applied_at DESC
  `);
  res.json(r.rows);
});

app.post('/api/leaves/:id/approve', requireAdmin, async (req, res) => {
  const leaveId = req.params.id;
  const { admin_comment } = req.body;
  try {
    const data = await pool.query(`
      SELECT l.*, s.name, s.email, s.hostel, s.year
      FROM leaves l JOIN students s ON l.student_id = s.id
      WHERE l.id=$1
    `, [leaveId]);

    if (data.rows.length === 0) return res.status(404).json({ error: 'Leave not found' });
    const leave = data.rows[0];

    // Generate PDF
    const pdfDir = path.join(__dirname, 'public', 'pdfs');
    if (!fs.existsSync(pdfDir)) fs.mkdirSync(pdfDir, { recursive: true });
    const pdfPath = path.join(pdfDir, `leave_${leaveId}.pdf`);

    const doc = new PDFDocument();
    doc.pipe(fs.createWriteStream(pdfPath));
    doc.fontSize(18).text('Hostel Leave Approval', { align: 'center' });
    doc.moveDown();
    doc.fontSize(12).text(`Student Name: ${leave.name}`);
    doc.text(`Email: ${leave.email}`);
    doc.text(`Hostel: ${leave.hostel}`);
    doc.text(`Year: ${leave.year}`);
    doc.text(`Leave Dates: ${leave.from_date} to ${leave.to_date}`);
    doc.moveDown();
    doc.text(`Admin Comment: ${admin_comment || 'Approved'}`);
    doc.text(`Status: Approved`);
    doc.end();

    const webPath = `/pdfs/leave_${leaveId}.pdf`;
    await pool.query(
      `UPDATE leaves SET status='accepted', admin_comment=$1, pdf_path=$2 WHERE id=$3`,
      [admin_comment || 'Approved', webPath, leaveId]
    );

    res.json({ message: 'Approved and PDF generated', pdf_url: webPath });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/leaves/:id/reject', requireAdmin, async (req, res) => {
  const leaveId = req.params.id;
  const { admin_comment } = req.body;
  try {
    await pool.query(`UPDATE leaves SET status='rejected', admin_comment=$1 WHERE id=$2`, [admin_comment || 'Rejected', leaveId]);
    res.json({ message: 'Leave rejected' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// AUTO PDF GENERATION WHEN ACCEPTED (for frontend or manual trigger)
app.get("/api/generate-pdf/:id", async (req, res) => {
  const leaveId = req.params.id;

  try {
    const data = await pool.query(`
      SELECT 
        l.id, l.student_id, l.from_date, l.to_date, l.reason, l.status, 
        l.applied_at, s.name, s.email, s.hostel, s.year
      FROM leaves l
      JOIN students s ON l.student_id = s.id
      WHERE l.id = $1
    `, [leaveId]);

    if (data.rows.length === 0)
      return res.status(404).json({ error: "Leave not found" });

    const leave = data.rows[0];

    if (leave.status.toLowerCase() !== "accepted")
      return res.status(400).json({ error: "PDF available only for accepted leaves" });

    const pdfDir = path.join(__dirname, "public", "pdfs");
    if (!fs.existsSync(pdfDir)) fs.mkdirSync(pdfDir, { recursive: true });

    const pdfPath = path.join(pdfDir, `leave_${leaveId}.pdf`);
    const doc = new PDFDocument({ margin: 40 });
    const writeStream = fs.createWriteStream(pdfPath);
    doc.pipe(writeStream);

    // Helper to format dates
    const formatDate = (d) => {
      if (!d) return "Not Available";
      return new Date(d).toLocaleString("en-IN", { 
        dateStyle: "medium", 
        timeStyle: "short" 
      });
    };

    // Header
    doc.rect(0, 0, 612, 70).fill("#0984e3");
    doc.fillColor("#fff").fontSize(20).font("Helvetica-Bold").text("HOSTEL LEAVE APPROVAL FORM", {
      align: "center",
      baseline: "middle",
    });
    doc.moveDown(2);

    // Student Info
    doc.fillColor("#000").fontSize(12).font("Helvetica");
    doc.text(`Student Name: ${leave.name}`);
    doc.text(`Student ID: ${leave.student_id}`);
    doc.text(`Applied Date: ${formatDate(leave.applied_at)}`);
    doc.text(`Email: ${leave.email}`);
    doc.text(`Hostel: ${leave.hostel}`);
    doc.text(`Year: ${leave.year}`);

    // Leave Details
    doc.moveDown(1.5);
    doc.font("Helvetica-Bold").fillColor("#0984e3").text("Leave Details", { underline: true });
    doc.moveDown(0.5);

    const tableTop = doc.y;
    const colWidths = [120, 120, 120, 120];
    const headers = ["From Date", "To Date", "Reason", "Status"];
    const values = [
      formatDate(leave.from_date),
      formatDate(leave.to_date),
      leave.reason,
      leave.status.toUpperCase(),
    ];

    let x = doc.page.margins.left;
    doc.font("Helvetica-Bold").fillColor("white").rect(x - 5, tableTop - 2, 480, 20).fill("#0984e3");
    headers.forEach((h, i) => {
      doc.fillColor("white").text(h, x + 5, tableTop, { width: colWidths[i], align: "center" });
      x += colWidths[i];
    });

    // Table row
    x = doc.page.margins.left;
    doc.fillColor("black").rect(x - 5, tableTop + 20, 480, 25).stroke();
    values.forEach((v, i) => {
      doc.text(v, x + 5, tableTop + 25, { width: colWidths[i], align: "center" });
      x += colWidths[i];
    });

    // Status
    doc.moveDown(3);
    doc.font("Helvetica-Bold").fillColor("#000").text("Leave Status: ");
    doc.font("Helvetica").fillColor("green").text("ACCEPTED");

    // Signature boxes
    doc.moveDown(3);
    const startY = doc.y;
    const boxWidth = 140, boxHeight = 40;

    doc.font("Helvetica-Bold").fillColor("#000").text("Student Signature:", 60, startY);
    doc.rect(60, startY + 10, boxWidth, boxHeight).stroke();

    doc.text("Parent Signature:", 230, startY);
    doc.rect(230, startY + 10, boxWidth, boxHeight).stroke();

    doc.text("RC / Warden Signature:", 400, startY);
    doc.rect(400, startY + 10, boxWidth, boxHeight).stroke();

    // Footer
    doc.moveDown(6);
    doc.fontSize(10).fillColor("gray").text("Generated by Hostel Leave Management System © 2025", { align: "center" });

    // Finish
    doc.end();

    writeStream.on("finish", async () => {
      const webPath = `/pdfs/leave_${leaveId}.pdf`;
      await pool.query(`UPDATE leaves SET pdf_path = $1 WHERE id = $2`, [webPath, leaveId]);
      res.json({ message: "PDF generated successfully", pdf_url: webPath });
    });

  } catch (err) {
    console.error("PDF generation error:", err);
    res.status(500).json({ error: "Error generating PDF" });
  }
});



/* ---------- START SERVER ---------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Server started on port ${PORT}`);
});
