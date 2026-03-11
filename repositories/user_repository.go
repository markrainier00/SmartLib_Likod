package repositories

import (
	"SmartLib_Likod/database"
	"SmartLib_Likod/model"
)

// Register an account (not yet approved by admin)
func CreateUser(user *model.User) error {
	return database.DB.Create(user).Error
}

// Looks if the email or school id exists (depends on what the user inputs betweeen those two) then collects details
func FindUserByEmailOrSchoolID(email, school_id string) (*model.User, error) {
	var user model.User
	result := database.DB.Where("email = ? OR school_id = ?", email, school_id).First(&user)
	return &user, result.Error
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
