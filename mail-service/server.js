import express from "express";
import nodemailer from "nodemailer";
import dotenv from "dotenv";

dotenv.config();
const app = express();
app.use(express.json());

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: 587,
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  },
  tls: { rejectUnauthorized: false }
});

app.post("/send-otp", async (req, res) => {
  const { to, otp } = req.body;

  try {
    await transporter.sendMail({
      from: `"Recruit Plus India" <${process.env.SMTP_USER}>`,
      to,
      subject: "Your Certificate Verification Code",
      html: `
        <h2>Your OTP</h2>
        <h1>${otp}</h1>
        <p>Valid for 10 minutes</p>
      `
    });
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Mail failed" });
  }
});

app.listen(3001, () => console.log("📧 Mail service running on http://localhost:3001"));
