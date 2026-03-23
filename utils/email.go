package utils

import (
	"fmt"
	"os"

	gomail "gopkg.in/gomail.v2"
)

func sendMail(toEmail, subject, body string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", os.Getenv("GMAIL_USER"))
	m.SetHeader("To", toEmail)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	d := gomail.NewDialer("smtp.gmail.com", 587, os.Getenv("GMAIL_USER"), os.Getenv("GMAIL_PASS"))
	return d.DialAndSend(m)
}

func SendOTPEmail(toEmail, otp string) error {
	return sendMail(toEmail, "SmartLib Registration OTP", fmt.Sprintf(`
		<div style="background:#f5f6fa; padding:40px 20px;">
			<div style="max-width:520px; margin:auto; background:#ffffff; border-radius:16px; box-shadow:0 10px 30px rgba(0,0,0,0.08); padding:32px 28px;">
				<div style="font-family: DM Sans, sans-serif; max-width: 480px; margin: auto; padding: 40px 24px;">
						<h2 style="color: #1a2744;">Registration OTP</h2>
						<p style="color: #475569;">A registration OTP was requested for your account.<br>
						<strong style="font-size:24px; letter-spacing:4px;">%s</strong>
						<br>This expires in <strong>5 minutes</strong>.</p>
				<div style="text-align:center; margin-top:16px;">
				</div>
						<p style="margin-top: 24px; font-size: 12px; color: #8a8ea8;">If you didn't request this, you can safely ignore this email.</p>
					</div>
					<div style="border-top:1px solid #e5e7eb; margin-top:24px; padding-top:16px; text-align:center;">
						<div style="font-family: 'DM Serif Display', serif; font-weight:bold; font-size:26px; color:#1a2744;">SmartLib</div>
						<div style="font-size:12px; color:#8a8ea8;">School Library Management Portal</div>
					</div>
			</div>
		</div>
	`, otp))
}

func SendResetEmail(toEmail, token string) error {
	resetLink := fmt.Sprintf("%s/reset-password?token=%s", os.Getenv("APP_URL"), token)
	return sendMail(toEmail, "Reset SmartLib Password", fmt.Sprintf(`
		<div style="background:#f5f6fa; padding:40px 20px;">
			<div style="max-width:520px; margin:auto; background:#ffffff; border-radius:16px; box-shadow:0 10px 30px rgba(0,0,0,0.08); padding:32px 28px;">
				<div style="font-family: DM Sans, sans-serif; max-width: 480px; margin: auto; padding: 40px 24px;">
						<h2 style="color: #1a2744;">Reset Your Password</h2>
						<p style="color: #475569;">A password reset was requested for your account.
						<br>If this was you, click the button below to create a new password.<br>
						<br>This expires in <strong>10 minutes</strong>.</p>
				<div style="text-align:center; margin-top:16px;">
					<a href="%s" style="display:inline-block; padding:12px 28px; background:#1a2744; color:#fff; border-radius:10px; text-decoration:none; font-weight:600;">
					Reset Password
					</a>
				</div>
						<p style="margin-top: 24px; font-size: 12px; color: #8a8ea8;">If you didn't request this, you can safely ignore this email.</p>
					</div>
					<div style="border-top:1px solid #e5e7eb; margin-top:24px; padding-top:16px; text-align:center;">
						<div style="font-family: 'DM Serif Display', serif; font-weight:bold; font-size:26px; color:#1a2744;">SmartLib</div>
						<div style="font-size:12px; color:#8a8ea8;">School Library Management Portal</div>
					</div>
			</div>
		</div>
	`, resetLink))
}

func SendApprovalEmail(toEmail, firstname string) error {
	return sendMail(toEmail, "Your SmartLib Account Has Been Approved!", fmt.Sprintf(`
		<div style="background:#f5f6fa; padding:40px 20px;">
			<div style="max-width:520px; margin:auto; background:#ffffff; border-radius:16px; box-shadow:0 10px 30px rgba(0,0,0,0.08); padding:32px 28px;">
				<div style="font-family: DM Sans, sans-serif; max-width: 480px; margin: auto; padding: 40px 24px;">
					<h2 style="color: #1a2744;">Welcome, %s!</h2>
					<p style="color: #475569;">Your library account has been <strong style="color: #2d7a4f;">approved</strong> by the Head Librarian.</p>
					<p style="color: #475569;">You can now sign in to SmartLib and start borrowing books.</p>
					<div style="text-align:center; margin-top:16px;">
						<a href="%s" style="display:inline-block; padding:12px 28px; background:#1a2744; color:#fff; border-radius:10px; text-decoration:none; font-weight:600;">
						Sign In Now
						</a>
					</div>
					<p style="margin-top: 24px; font-size: 12px; color: #8a8ea8;">If you have any questions, please contact the library.</p>
				</div>
				<div style="border-top:1px solid #e5e7eb; margin-top:24px; padding-top:16px; text-align:center;">
					<div style="font-family: 'DM Serif Display', serif; font-weight:bold; font-size:26px; color:#1a2744;">SmartLib</div>
					<div style="font-size:12px; color:#8a8ea8;">School Library Management Portal</div>
				</div>
			</div>
		</div>
	`, firstname, os.Getenv("APP_URL")))
}

func SendRejectionEmail(toEmail, firstname, reason string) error {
	return sendMail(toEmail, "Your SmartLib Account Registration Update", fmt.Sprintf(`
		<div style="background:#f5f6fa; padding:40px 20px;">
			<div style="max-width:520px; margin:auto; background:#ffffff; border-radius:16px; box-shadow:0 10px 30px rgba(0,0,0,0.08); padding:32px 28px;">
				<div style="font-family: DM Sans, sans-serif; max-width: 480px; margin: auto; padding: 40px 24px;">
					<h2 style="color: #1a2744;">Hi %s,</h2>
					<p style="color: #475569;">Unfortunately, your library account registration has been <strong style="color: #c94040;">rejected</strong> by the Head Librarian.</p>
					<div style="background:#fff0f0; border-left:4px solid #c94040; padding:12px 16px; border-radius:6px; margin:16px 0;">
						<p style="margin:0; font-size:13px; color:#c94040;"><strong>Reason:</strong> %s</p>
					</div>
					<p style="color: #475569; font-size: 13px;">If you believe this is a mistake, please contact the library directly.</p>
				</div>
				<div style="border-top:1px solid #e5e7eb; margin-top:24px; padding-top:16px; text-align:center;">
					<div style="font-family: 'DM Serif Display', serif; font-weight:bold; font-size:26px; color:#1a2744;">SmartLib</div>
					<div style="font-size:12px; color:#8a8ea8;">School Library Management Portal</div>
				</div>
			</div>
		</div>
	`, firstname, reason))
}
