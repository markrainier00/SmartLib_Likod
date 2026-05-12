package repositories

import (
	"SmartLib_Likod/database"
	"SmartLib_Likod/model"
)

// Register an account (not yet approved by admin)
func CreateUser(user *model.User) error {
	return database.DB.Create(user).Error
}

// Looks if the email exists
func FindUserByEmail(email string) (*model.User, error) {
	var user model.User
	result := database.DB.Where("email = ?", email).First(&user)
	return &user, result.Error
}

// Looks if the school id exists
func FindUserBySchoolID(school_id string) (*model.User, error) {
	var user model.User
	result := database.DB.Where("school_id = ?", school_id).First(&user)
	return &user, result.Error
}

// Looks if the email or school id exists (depends on what the user inputs betweeen those two) then collects details
func FindUserByEmailOrSchoolID(email, school_id string) (*model.User, error) {
	var user model.User
	result := database.DB.Where("email = ? OR school_id = ?", email, school_id).First(&user)
	return &user, result.Error
}

func CreateSigninHistory(entry *model.SigninHistory) error {
	return database.DB.Create(entry).Error
}

func GetSigninHistoryByUserID(userID uint, limit int) ([]model.SigninHistory, error) {
	var history []model.SigninHistory
	result := database.DB.
		Where("user_id = ?", userID).
		Order("signin_at DESC").
		Limit(limit).
		Find(&history)
	return history, result.Error
}

// Deletes old OTP for user that wants to create new OTP before saving it
func CreateOTPCode(code *model.OTPCode) error {
	database.DB.Where("email = ? AND used = false", code.Email).Delete(&model.OTPCode{})
	return database.DB.Create(code).Error
}

// Looks for the OTP and see if it is already used
func FindOTPCode(email, otp string) (*model.OTPCode, error) {
	var code model.OTPCode
	result := database.DB.Where("email = ? AND otp = ? AND used = false", email, otp).First(&code)
	return &code, result.Error
}

// Updates OTP as used
func MarkOTPUsed(email, otp string) error {
	return database.DB.Model(&model.OTPCode{}).Where("email = ? AND otp = ?", email, otp).Update("used", true).Error
}

// Deletes old token for user that wants to create new token before saving it
func CreatePasswordReset(reset *model.PasswordReset) error {
	database.DB.Where("user_id = ? AND used = false", reset.UserID).Delete(&model.PasswordReset{})
	return database.DB.Create(reset).Error
}

// Looks for the password reset token and see if it is already used
func FindPasswordResetByToken(token string) (*model.PasswordReset, error) {
	var reset model.PasswordReset
	result := database.DB.Where("token = ? AND used = false", token).First(&reset)
	return &reset, result.Error
}

// Updates user's password
func UpdateUserPassword(UserID uint, hashedPassword string) error {
	return database.DB.Model(&model.User{}).Where("id = ?", UserID).Update("password", hashedPassword).Error
}

// Updates password reset token as used
func MarkTokenUsed(token string) error {
	return database.DB.Model(&model.PasswordReset{}).Where("token = ?", token).Update("used", true).Error
}

// ==========================================
// 🚀 BAGONG DAGDAG: ADMIN REGISTRATION APPROVALS
// ==========================================

// GetAllRegistrations - Kinukuha lahat ng nag-register
func GetAllRegistrations() ([]model.User, error) {
	var users []model.User
	err := database.DB.Order("created_at desc").Find(&users).Error
	return users, err
}

// UpdateUserStatus - Para ma-Approve (Active) o ma-Reject (Rejected)
func UpdateUserStatus(schoolID string, status string, rejectReason string) error {
	return database.DB.Model(&model.User{}).
		Where("school_id = ?", schoolID).
		Updates(map[string]interface{}{
			"status":        status,
			"reject_reason": rejectReason,
		}).Error
}

// ==========================================
// 🚀 MANAGE ACCOUNTS (LOCK/UNLOCK & DELETE)
// ==========================================

// UpdateAccountStatus - Para sa Lock at Unlock (Admin manual action)
func UpdateAccountStatus(schoolID string, status string) error {
	updates := map[string]interface{}{"status": status}

	// Kung i-u-unlock ng Admin, i-reset natin ang penalty to 0 para may fresh start ang estudyante
	if status == "Active" {
		updates["penalty_count"] = 0
	}

	return database.DB.Model(&model.User{}).Where("school_id = ?", schoolID).Updates(updates).Error
}

// DeleteUserBySchoolID - Para mabura ang record ng pasaway na student
func DeleteUserBySchoolID(schoolID string) error {
	return database.DB.Where("school_id = ?", schoolID).Delete(&model.User{}).Error
}

func GetUsersByRole(role string) ([]model.User, error) {
	var users []model.User
	err := database.DB.Where("role = ? AND status = ?", role, "Active").Find(&users).Error
	return users, err
}

func GetWishlistNotifyUsersByBook(ISBN string) ([]string, error) {
	var schoolIDs []string
	err := database.DB.Table("wishlists").
		Select("school_id").
		Where("isbn = ? AND status = ?", ISBN, "Notify").
		Scan(&schoolIDs).Error
	return schoolIDs, err
}
