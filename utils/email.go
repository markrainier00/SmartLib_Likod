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
						<svg width="30" height="30" viewBox="0 0 540.000000 452.000000"  preserveAspectRatio="xMidYMid meet">
							<g transform="translate(0.000000,452.000000) scale(0.100000,-0.100000)" fill="#1B5E35">
							<path d="M4260 4030 l0 -230 220 0 220 0 0 -120 0 -120 220 0 220 0 0 230 0 230 -220 0 -220 0 0 120 0 120 -220 0 -220 0 0 -230z"/>
							<path d="M3610 3710 l0 -170 -27 -6 c-47 -11 -206 -64 -248 -84 -22 -10 -58 -26 -80 -35 -70 -30 -198 -94 -250 -125 -27 -17 -57 -34 -65 -37 -8 -4 -19 -11 -25 -15 -12 -10 -184 -130 -220 -154 -25 -16 -27 -16 -63 13 -99 79 -336 225 -465 286 -259 124 -522 198 -836 237 -192 23 -526 0 -695 -48 -36 -10 -42 -29 -45 -137 -1 -44 -6 -199 -11 -345 -6 -146 -19 -526 -30 -845 -11 -319 -25 -709 -31 -868 -6 -158 -8 -294 -5 -303 7 -18 28 -17 161 9 148 28 309 40 525 40 236 1 310 -8 560 -63 19 -4 51 -11 70 -15 60 -13 296 -94 377 -131 138 -62 261 -124 272 -138 11 -13 11 -17 -2 -22 -15 -5 -45 1 -209 45 -139 37 -222 58 -283 70 -33 7 -78 16 -100 21 -22 5 -80 14 -130 20 -49 6 -119 17 -155 23 -42 8 -191 12 -420 11 -330 0 -485 -8 -734 -35 -81 -10 -100 -9 -108 2 -11 17 -8 81 52 1044 5 88 14 234 20 325 6 91 15 237 20 325 6 88 14 232 20 320 5 88 12 196 16 241 l7 81 -33 12 c-70 24 -168 5 -193 -39 -22 -39 -45 -286 -87 -950 -10 -163 -22 -340 -40 -615 -5 -77 -14 -219 -20 -315 -6 -96 -15 -222 -21 -280 -5 -58 -9 -159 -9 -226 0 -118 0 -121 27 -146 53 -48 45 -47 933 -69 223 -5 596 -13 830 -17 234 -5 431 -12 438 -16 6 -4 27 -30 46 -59 68 -101 174 -157 313 -165 68 -4 93 -1 147 18 82 29 151 81 194 145 19 28 40 54 48 58 8 4 238 12 512 18 687 13 1255 27 1457 35 176 7 219 18 253 62 15 19 16 178 3 354 -6 68 -15 200 -21 293 -6 94 -15 224 -20 290 -5 66 -14 194 -20 285 -6 91 -15 226 -20 300 -5 74 -12 183 -16 243 l-6 107 -125 0 -126 0 7 -97 c4 -54 11 -165 16 -248 5 -82 14 -221 20 -308 5 -86 15 -228 20 -315 6 -86 15 -224 20 -307 24 -364 24 -374 8 -380 -8 -3 -70 -1 -139 5 -169 15 -398 28 -619 36 -177 7 -361 -3 -515 -26 -33 -5 -98 -14 -145 -20 -47 -7 -103 -16 -125 -20 -22 -5 -62 -14 -90 -20 -52 -11 -377 -91 -453 -111 -44 -12 -72 -3 -58 20 8 12 107 60 301 146 109 49 437 140 585 164 271 43 622 40 905 -9 33 -5 86 -13 117 -16 l57 -7 3 39 c2 22 0 102 -4 179 -21 432 -29 608 -38 865 -6 157 -13 318 -16 358 l-6 72 -284 0 -284 0 0 230 0 230 -220 0 -220 0 0 -230 0 -230 -75 0 -75 0 0 423 0 422 215 -2 215 -2 0 234 0 235 -215 0 -215 0 0 -170z m-2345 -355 c283 -34 509 -89 740 -181 95 -37 439 -212 498 -253 l47 -32 0 -954 c0 -913 -1 -955 -18 -955 -10 0 -22 4 -27 9 -11 10 -165 88 -236 120 -125 56 -346 130 -474 160 -27 7 -66 16 -85 21 -130 31 -244 46 -460 60 -152 10 -250 5 -416 -21 -34 -5 -72 -9 -84 -9 l-23 0 7 183 c4 100 11 306 16 457 5 151 14 412 20 580 6 168 14 412 19 543 5 186 10 240 22 252 9 10 53 17 134 23 174 13 188 13 320 -3z"/>
							<path d="M4260 3180 l0 -230 220 0 220 0 0 230 0 230 -220 0 -220 0 0 -230z"/>
							<path d="M4860 3030 l0 -230 215 0 215 0 0 230 0 230 -215 0 -215 0 0 -230z"/>
							</g>
						</svg>
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
			<div style="background: #f5f6fa; padding:40px 20px;">
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
						<svg width="30" height="30" viewBox="0 0 540.000000 452.000000"  preserveAspectRatio="xMidYMid meet">
							<g transform="translate(0.000000,452.000000) scale(0.100000,-0.100000)" fill="#1B5E35">
							<path d="M4260 4030 l0 -230 220 0 220 0 0 -120 0 -120 220 0 220 0 0 230 0 230 -220 0 -220 0 0 120 0 120 -220 0 -220 0 0 -230z"/>
							<path d="M3610 3710 l0 -170 -27 -6 c-47 -11 -206 -64 -248 -84 -22 -10 -58 -26 -80 -35 -70 -30 -198 -94 -250 -125 -27 -17 -57 -34 -65 -37 -8 -4 -19 -11 -25 -15 -12 -10 -184 -130 -220 -154 -25 -16 -27 -16 -63 13 -99 79 -336 225 -465 286 -259 124 -522 198 -836 237 -192 23 -526 0 -695 -48 -36 -10 -42 -29 -45 -137 -1 -44 -6 -199 -11 -345 -6 -146 -19 -526 -30 -845 -11 -319 -25 -709 -31 -868 -6 -158 -8 -294 -5 -303 7 -18 28 -17 161 9 148 28 309 40 525 40 236 1 310 -8 560 -63 19 -4 51 -11 70 -15 60 -13 296 -94 377 -131 138 -62 261 -124 272 -138 11 -13 11 -17 -2 -22 -15 -5 -45 1 -209 45 -139 37 -222 58 -283 70 -33 7 -78 16 -100 21 -22 5 -80 14 -130 20 -49 6 -119 17 -155 23 -42 8 -191 12 -420 11 -330 0 -485 -8 -734 -35 -81 -10 -100 -9 -108 2 -11 17 -8 81 52 1044 5 88 14 234 20 325 6 91 15 237 20 325 6 88 14 232 20 320 5 88 12 196 16 241 l7 81 -33 12 c-70 24 -168 5 -193 -39 -22 -39 -45 -286 -87 -950 -10 -163 -22 -340 -40 -615 -5 -77 -14 -219 -20 -315 -6 -96 -15 -222 -21 -280 -5 -58 -9 -159 -9 -226 0 -118 0 -121 27 -146 53 -48 45 -47 933 -69 223 -5 596 -13 830 -17 234 -5 431 -12 438 -16 6 -4 27 -30 46 -59 68 -101 174 -157 313 -165 68 -4 93 -1 147 18 82 29 151 81 194 145 19 28 40 54 48 58 8 4 238 12 512 18 687 13 1255 27 1457 35 176 7 219 18 253 62 15 19 16 178 3 354 -6 68 -15 200 -21 293 -6 94 -15 224 -20 290 -5 66 -14 194 -20 285 -6 91 -15 226 -20 300 -5 74 -12 183 -16 243 l-6 107 -125 0 -126 0 7 -97 c4 -54 11 -165 16 -248 5 -82 14 -221 20 -308 5 -86 15 -228 20 -315 6 -86 15 -224 20 -307 24 -364 24 -374 8 -380 -8 -3 -70 -1 -139 5 -169 15 -398 28 -619 36 -177 7 -361 -3 -515 -26 -33 -5 -98 -14 -145 -20 -47 -7 -103 -16 -125 -20 -22 -5 -62 -14 -90 -20 -52 -11 -377 -91 -453 -111 -44 -12 -72 -3 -58 20 8 12 107 60 301 146 109 49 437 140 585 164 271 43 622 40 905 -9 33 -5 86 -13 117 -16 l57 -7 3 39 c2 22 0 102 -4 179 -21 432 -29 608 -38 865 -6 157 -13 318 -16 358 l-6 72 -284 0 -284 0 0 230 0 230 -220 0 -220 0 0 -230 0 -230 -75 0 -75 0 0 423 0 422 215 -2 215 -2 0 234 0 235 -215 0 -215 0 0 -170z m-2345 -355 c283 -34 509 -89 740 -181 95 -37 439 -212 498 -253 l47 -32 0 -954 c0 -913 -1 -955 -18 -955 -10 0 -22 4 -27 9 -11 10 -165 88 -236 120 -125 56 -346 130 -474 160 -27 7 -66 16 -85 21 -130 31 -244 46 -460 60 -152 10 -250 5 -416 -21 -34 -5 -72 -9 -84 -9 l-23 0 7 183 c4 100 11 306 16 457 5 151 14 412 20 580 6 168 14 412 19 543 5 186 10 240 22 252 9 10 53 17 134 23 174 13 188 13 320 -3z"/>
							<path d="M4260 3180 l0 -230 220 0 220 0 0 230 0 230 -220 0 -220 0 0 -230z"/>
							<path d="M4860 3030 l0 -230 215 0 215 0 0 230 0 230 -215 0 -215 0 0 -230z"/>
							</g>
						</svg>
						<div style="font-family: 'DM Serif Display', serif; font-weight:bold; font-size:26px; color: #1B5E35;">SmartLib</div>
						<div style="font-size:12px; color: #8da88a;">School Library Management Portal</div>
					</div>
				</div>
			</div>
		`, resetLink),
	)
}

func SendAdminWelcomeEmail(toEmail, firstname, tempPassword string) error {
	// ... yung HTML template na ginawa natin kanina ...
	return sendMail(toEmail, "Welcome to SmartLib Admin Team!", fmt.Sprintf("Hello %s, your temp password is %s", firstname, tempPassword))
}

// Idagdag mo rin dito ang SendApprovalEmail at SendRejectionEmail kung ginagamit mo sila
