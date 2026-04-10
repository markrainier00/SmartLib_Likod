package utils

import (
	"fmt"
	"os"

	gomail "gopkg.in/gomail.v2"
)

// Private helper (maliit ang 's')
func sendMail(toEmail, subject, body string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", os.Getenv("GMAIL_USER"))
	m.SetHeader("To", toEmail)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	d := gomail.NewDialer("smtp.gmail.com", 587, os.Getenv("GMAIL_USER"), os.Getenv("GMAIL_PASS"))
	return d.DialAndSend(m)
}

// PUBLIC functions (Dapat malaki ang unang letra)
func SendOTPEmail(toEmail, otp string) error {
	return sendMail(toEmail, "SmartLib Registration OTP", fmt.Sprintf("OTP: %s", otp))
}

func SendResetEmail(toEmail, token string) error {
	return sendMail(toEmail, "Reset Password", fmt.Sprintf("Token: %s", token))
}

func SendAdminWelcomeEmail(toEmail, firstname, tempPassword string) error {
	// ... yung HTML template na ginawa natin kanina ...
	return sendMail(toEmail, "Welcome to SmartLib Admin Team!", fmt.Sprintf("Hello %s, your temp password is %s", firstname, tempPassword))
}

// Idagdag mo rin dito ang SendApprovalEmail at SendRejectionEmail kung ginagamit mo sila
