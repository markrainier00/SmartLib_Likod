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
	return sendMail(
		toEmail,
		"SmartLib Registration OTP",
		fmt.Sprintf(`
			<div style="background: #f5faf5; padding:40px 20px;">
				<div style="max-width:520px; margin:auto; background: #ffffff; border-radius:16px; box-shadow:0 10px 30px rgba(0,0,0,0.08); padding:32px 28px;">
					<div style="font-family: DM Sans, sans-serif; max-width: 480px; margin: auto; padding: 40px 24px;">
						<h2 style="color: #1B5E35;">Registration OTP</h2>
						<p style="color: #476954;">
							A registration OTP was requested for your account.<br>
							<strong style="font-size:24px; letter-spacing:4px;">%s</strong>
							<br>This expires in <strong>5 minutes</strong>.
							</p>
						<p style="margin-top: 24px; font-size: 12px; color: #8da88a;">If you didn't request this, you can safely ignore this email.</p>
					</div>
					<div style="border-top:1px solid #e6ebe5; margin-top:24px; padding-top:16px; text-align:center;">
						<div style="font-family: 'DM Serif Display', serif; font-weight:bold; font-size:26px; color: #1B5E35;">SmartLib</div>
						<div style="font-size:12px; color: #8da88a;">School Library Management Portal</div>
					</div>
				</div>
			</div>
		`, otp),
	)
}

func SendResetEmail(toEmail, token string) error {
	resetLink := fmt.Sprintf("%s/reset-password?token=%s", os.Getenv("APP_URL"), token)
	return sendMail(
		toEmail,
		"Reset SmartLib Password",
		fmt.Sprintf(`
			<div style="background: #f5faf5; padding:40px 20px;">
				<div style="max-width:520px; margin:auto; background: #ffffff; border-radius:16px; box-shadow:0 10px 30px rgba(0,0,0,0.08); padding:32px 28px;">
					<div style="font-family: DM Sans, sans-serif; max-width: 480px; margin: auto; padding: 40px 24px;">
						<h2 style="color: #1B5E35;">Reset Your Password</h2>
						<p style="color: #476954;">
							A password reset was requested for your account.
							<br>If this was you, click the button below to create a new password.<br>
							<br>This expires in <strong>10 minutes</strong>.
						</p>
						<div style="text-align:center; margin-top:16px;">
							<a href="%s" style="display:inline-block; padding:12px 28px; background: #1B5E35; color: #fff; border-radius:10px; text-decoration:none; font-weight:600;">Reset Password</a>
						</div>
						<p style="margin-top: 24px; font-size: 12px; color: #8da88a;">If you didn't request this, you can safely ignore this email.</p>
					</div>
					<div style="border-top:1px solid #e6ebe5; margin-top:24px; padding-top:16px; text-align:center;">
						<div style="font-family: 'DM Serif Display', serif; font-weight:bold; font-size:26px; color: #1B5E35;">SmartLib</div>
						<div style="font-size:12px; color: #8da88a;">School Library Management Portal</div>
					</div>
				</div>
			</div>
		`, resetLink),
	)
}

func SendStudentWelcomeEmail(toEmail, name string) error {
	return sendMail(
		toEmail,
		"Welcome to SmartLib Team!",
		fmt.Sprintf(`
			<div style="background: #f6faf5; padding:40px 20px;">
				<div style="max-width:520px; margin:auto; background: #ffffff; border-radius:16px; box-shadow:0 10px 30px rgba(0,0,0,0.08); padding:32px 28px;">
					<div style="font-family: DM Sans, sans-serif; max-width: 480px; margin: auto; padding: 40px 24px;">
						<h2 style="color: #1B5E35;">Welcome to SmartLib Team!</h2>
						<p style="color: #476954; margin-bottom: 10px">Hello %s!</p>
						<p style="color: #476954;">Your registration for SmartLib has been approved.<br/>
							You can now <a href="%s" style="color: #1B5E35; text-decoration:underline;">sign in</a> to your account and start accessing the library’s resources and borrow books.</p>
					</div>
					<div style="border-top:1px solid #e6ebe5; margin-top:24px; padding-top:16px; text-align:center;">
						<div style="font-family: 'DM Serif Display', serif; font-weight:bold; font-size:26px; color: #1B5E35;">SmartLib</div>
						<div style="font-size:12px; color: #8da88a;">School Library Management Portal</div>
					</div>
				</div>
			</div>
		`, name, os.Getenv("APP_URL")),
	)
}

func SendRegisterRejectionEmail(name, toEmail, reason string) error {
	return sendMail(
		toEmail,
		"Registration Request Rejection",
		fmt.Sprintf(`
			<div style="background: #f5faf5; padding:40px 20px;">
				<div style="max-width:520px; margin:auto; background: #ffffff; border-radius:16px; box-shadow:0 10px 30px rgba(0,0,0,0.08); padding:32px 28px;">
					<div style="font-family: DM Sans, sans-serif; max-width: 480px; margin: auto; padding: 40px 24px;">
						<h2 style="color: #B91C1C;">Registration Request Rejection</h2>
						<p style="color: #476954; margin-bottom: 10px">Dear %s,</p>
						<p style="color: #476954;">We regret to inform you that your registration request for SmartLib has been rejected.</p>
						<p style="color: #1B5E35;"><strong>Reason:</strong><br/>%s</p>
						<p style="color: #476954;">Thank you for your interest in SmartLib.</p>
						<p style="margin-top: 24px; font-size: 12px; color: #8da88a;">If you didn't registered in SmartLib, you can safely ignore this email.</p>
					</div>
					<div style="border-top:1px solid #e6ebe5; margin-top:24px; padding-top:16px; text-align:center;">
						<div style="font-family: 'DM Serif Display', serif; font-weight:bold; font-size:26px; color: #1B5E35;">SmartLib</div>
						<div style="font-size:12px; color: #8da88a;">School Library Management Portal</div>
					</div>
				</div>
			</div>
		`, name, reason),
	)
}

func SendAdminWelcomeEmail(toEmail, firstname, tempPassword string) error {
	return sendMail(
		toEmail,
		"Welcome to SmartLib Team!",
		fmt.Sprintf(`
			<div style="background: #f5faf5; padding:40px 20px;">
				<div style="max-width:520px; margin:auto; background: #ffffff; border-radius:16px; box-shadow:0 10px 30px rgba(0,0,0,0.08); padding:32px 28px;">
					<div style="font-family: DM Sans, sans-serif; max-width: 480px; margin: auto; padding: 40px 24px;">
						<h2 style="color: #1B5E35;">Account Created</h2>
						<p style="color: #476954; margin-bottom: 10px">Hello %s!</p>
						<p style="color: #476954; margin-bottom: 10px">Your staff account for SmartLib has been successfully created.</p>
						<p style="color: #1B5E35;">Temporary Password: <strong>%s</strong></p>
						<p style="margin-top: 24px; font-size: 12px; color: #8da88a;">Please <strong><a href="%s" style="color: #1B5E35; text-decoration:underline;">sign in</a></strong> as soon as possible and change your password immediately.</p>
					</div>
					<div style="border-top:1px solid #e6ebe5; margin-top:24px; padding-top:16px; text-align:center;">
						<div style="font-family: 'DM Serif Display', serif; font-weight:bold; font-size:26px; color: #1B5E35;">SmartLib</div>
						<div style="font-size:12px; color: #8da88a;">School Library Management Portal</div>
					</div>
				</div>
			</div>
		`, firstname, tempPassword, os.Getenv("APP_URL")))
}

func SendAccountLockedEmail(toEmail, name string) error {
	return sendMail(
		toEmail,
		"SmartLib Account Locked",
		fmt.Sprintf(`
			<div style="background: #f5faf5; padding:40px 20px;">
				<div style="max-width:520px; margin:auto; background: #ffffff; border-radius:16px; box-shadow:0 10px 30px rgba(0,0,0,0.08); padding:32px 28px;">
					<div style="font-family: DM Sans, sans-serif; max-width: 480px; margin: auto; padding: 40px 24px;">
						<h2 style="color: #B91C1C;">Account Locked</h2>
						<p style="color: #476954; margin-bottom: 10px">Dear %s,</p>
						<p style="color: #476954;">Your SmartLib account has been <strong style="color:#B91C1C;">locked</strong> due to accumulating <strong>3 borrow offenses</strong>.</p>
						<p style="color: #476954;">You will no longer be able to sign in until your account is unlocked by a library staff.</p>
						<p style="color: #476954;">To regain access, please do either of the following:</p>
						<ul style="color: #476954; padding-left: 20px;">
							<li>Visit the library in person and speak with a library staff.</li>
							<li>Message the library directly to request an account unlock.</li>
						</ul>
						<p style="margin-top: 24px; font-size: 12px; color: #8da88a;">If you believe this is a mistake, please contact the library as soon as possible.</p>
					</div>
					<div style="border-top:1px solid #e6ebe5; margin-top:24px; padding-top:16px; text-align:center;">
						<div style="font-family: 'DM Serif Display', serif; font-weight:bold; font-size:26px; color: #1B5E35;">SmartLib</div>
						<div style="font-size:12px; color: #8da88a;">School Library Management Portal</div>
					</div>
				</div>
			</div>
		`, name),
	)
}

func SendManualLockEmail(toEmail, name, reason string) error {
	return sendMail(
		toEmail,
		"SmartLib Account Locked",
		fmt.Sprintf(`
			<div style="background: #f5faf5; padding:40px 20px;">
				<div style="max-width:520px; margin:auto; background: #ffffff; border-radius:16px; box-shadow:0 10px 30px rgba(0,0,0,0.08); padding:32px 28px;">
					<div style="font-family: DM Sans, sans-serif; max-width: 480px; margin: auto; padding: 40px 24px;">
						<h2 style="color: #B91C1C;">Account Locked</h2>
						<p style="color: #476954; margin-bottom: 10px">Dear %s,</p>
						<p style="color: #476954;">Your SmartLib account has been <strong style="color:#B91C1C;">locked</strong> by a library staff.</p>
						<p style="color: #1B5E35;"><strong>Reason:</strong><br/>%s</p>
						<p style="color: #476954;">You will not be able to sign in until your account is unlocked. To regain access, please:</p>
						<ul style="color: #476954; padding-left: 20px;">
							<li>Visit the library in person and speak with a library staff.</li>
							<li>Message the library directly to request an account unlock.</li>
						</ul>
						<p style="margin-top: 24px; font-size: 12px; color: #8da88a;">If you believe this is a mistake, please contact the library as soon as possible.</p>
					</div>
					<div style="border-top:1px solid #e6ebe5; margin-top:24px; padding-top:16px; text-align:center;">
						<div style="font-family: 'DM Serif Display', serif; font-weight:bold; font-size:26px; color: #1B5E35;">SmartLib</div>
						<div style="font-size:12px; color: #8da88a;">School Library Management Portal</div>
					</div>
				</div>
			</div>
		`, name, reason),
	)
}

func SendArchiveEmail(toEmail, name, reason string) error {
	return sendMail(
		toEmail,
		"SmartLib Account Disabled",
		fmt.Sprintf(`
			<div style="background: #f5faf5; padding:40px 20px;">
				<div style="max-width:520px; margin:auto; background: #ffffff; border-radius:16px; box-shadow:0 10px 30px rgba(0,0,0,0.08); padding:32px 28px;">
					<div style="font-family: DM Sans, sans-serif; max-width: 480px; margin: auto; padding: 40px 24px;">
						<h2 style="color: #B91C1C;">Account Disabled</h2>
						<p style="color: #476954; margin-bottom: 10px">Dear %s,</p>
						<p style="color: #476954;">Your SmartLib account has been <strong style="color:#B91C1C;">disabled</strong> by a library staff.</p>
						<p style="color: #1B5E35;"><strong>Reason:</strong><br/>%s</p>
						<p style="color: #476954;">You will no longer be able to access SmartLib. If you believe this is an error, please contact the library directly.</p>
						<p style="margin-top: 24px; font-size: 12px; color: #8da88a;">If you didn't have an account in SmartLib, you can safely ignore this email.</p>
					</div>
					<div style="border-top:1px solid #e6ebe5; margin-top:24px; padding-top:16px; text-align:center;">
						<div style="font-family: 'DM Serif Display', serif; font-weight:bold; font-size:26px; color: #1B5E35;">SmartLib</div>
						<div style="font-size:12px; color: #8da88a;">School Library Management Portal</div>
					</div>
				</div>
			</div>
		`, name, reason),
	)
}

func SendAccountUnlockedEmail(toEmail, name string) error {
	return sendMail(
		toEmail,
		"SmartLib Account Unlocked",
		fmt.Sprintf(`
			<div style="background: #f5faf5; padding:40px 20px;">
				<div style="max-width:520px; margin:auto; background: #ffffff; border-radius:16px; box-shadow:0 10px 30px rgba(0,0,0,0.08); padding:32px 28px;">
					<div style="font-family: DM Sans, sans-serif; max-width: 480px; margin: auto; padding: 40px 24px;">
						<h2 style="color: #1B5E35;">Account Unlocked</h2>
						<p style="color: #476954; margin-bottom: 10px">Dear %s,</p>
						<p style="color: #476954;">Your SmartLib account has been <strong style="color:#1B5E35;">unlocked</strong> by a library staff.</p>
						<p style="color: #476954;">You can now <a href="%s" style="color: #1B5E35; text-decoration:underline;">sign in</a> and borrow books again.</p>
						<p style="margin-top: 24px; font-size: 12px; color: #8da88a;">Please make sure to follow library policies to avoid future restrictions.</p>
					</div>
					<div style="border-top:1px solid #e6ebe5; margin-top:24px; padding-top:16px; text-align:center;">
						<div style="font-family: 'DM Serif Display', serif; font-weight:bold; font-size:26px; color: #1B5E35;">SmartLib</div>
						<div style="font-size:12px; color: #8da88a;">School Library Management Portal</div>
					</div>
				</div>
			</div>
		`, name, os.Getenv("APP_URL")),
	)
}

func SendAccountUnarchivedEmail(toEmail, name string) error {
	return sendMail(
		toEmail,
		"SmartLib Account Restored",
		fmt.Sprintf(`
			<div style="background: #f5faf5; padding:40px 20px;">
				<div style="max-width:520px; margin:auto; background: #ffffff; border-radius:16px; box-shadow:0 10px 30px rgba(0,0,0,0.08); padding:32px 28px;">
					<div style="font-family: DM Sans, sans-serif; max-width: 480px; margin: auto; padding: 40px 24px;">
						<h2 style="color: #1B5E35;">Account Restored</h2>
						<p style="color: #476954; margin-bottom: 10px">Dear %s,</p>
						<p style="color: #476954;">Your SmartLib account has been <strong style="color:#1B5E35;">restored</strong> by a library staff and is now active again.</p>
						<p style="color: #476954;">You can now <a href="%s" style="color: #1B5E35; text-decoration:underline;">sign in</a> and access the library's resources.</p>
						<p style="margin-top: 24px; font-size: 12px; color: #8da88a;">If you have any concerns, please don't hesitate to contact the library.</p>
					</div>
					<div style="border-top:1px solid #e6ebe5; margin-top:24px; padding-top:16px; text-align:center;">
						<div style="font-family: 'DM Serif Display', serif; font-weight:bold; font-size:26px; color: #1B5E35;">SmartLib</div>
						<div style="font-size:12px; color: #8da88a;">School Library Management Portal</div>
					</div>
				</div>
			</div>
		`, name, os.Getenv("APP_URL")),
	)
}
