package services

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"time"

	"SmartLib_Likod/database"
	"SmartLib_Likod/model"
	"SmartLib_Likod/model/status"
	"SmartLib_Likod/repositories"
	"SmartLib_Likod/utils"

	"golang.org/x/crypto/bcrypt"
)

type SendOTPInput struct {
	Email string `json:"email"`
}

type VerifyOTPInput struct {
	Email string `json:"email"`
	OTP   string `json:"otp"`
}

type CheckSchoolIDInput struct {
	SchoolID string `json:"school_id"`
}

type RegisterUserInput struct {
	FirstName     string `json:"firstname"`
	LastName      string `json:"lastname"`
	Email         string `json:"email"`
	SchoolID      string `json:"school_id"`
	Department    string `json:"department"`
	Program       string `json:"program"`
	Year          string `json:"year"`
	Password      string `json:"password"`
	SchoolIDImage string `json:"school_id_image"`
}

type RegisterStaffInput struct {
	FirstName string `json:"firstname"`
	LastName  string `json:"lastname"`
	Email     string `json:"email"`
}

type SigninInput struct {
	Identifier string `json:"identifier"`
	Password   string `json:"password"`
}

type ForgotPasswordInput struct {
	Identifier string `json:"identifier"`
}

type ResetPasswordInput struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

type ChangePasswordInput struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

type ChangeInformationInput struct {
	School_ID  string `json:"school_id"`
	Email      string `json:"email"`
	Department string `json:"department"`
	Program    string `json:"program"`
	Year       string `json:"year"`
}

type ApproveRejectInput struct {
	SchoolID string `json:"school_id"`
	Reason   string `json:"reason,omitempty"`
}

func SendOTPService(input SendOTPInput) error {
	user, err := repositories.FindUserByEmail(input.Email)
	if err == nil && user != nil {
		return errors.New("Email already registered")
	}

	max := big.NewInt(1000000)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return errors.New("failed to generate OTP")
	}

	otp := fmt.Sprintf("%06d", n.Int64())

	verify := &model.OTPCode{
		Email:     input.Email,
		OTP:       otp,
		ExpiresAt: time.Now().Add(5 * time.Minute),
		Used:      false,
	}

	if err := repositories.CreateOTPCode(verify); err != nil {
		return errors.New("failed to create OTP")
	}

	if err := utils.SendOTPEmail(input.Email, otp); err != nil {
		return errors.New("failed to send OTP email")
	}

	return nil
}

func VerifyOTPService(input VerifyOTPInput) error {
	verify, err := repositories.FindOTPCode(input.Email, input.OTP)
	if err != nil {
		return errors.New("Invalid or expired OTP")
	}

	if time.Now().After(verify.ExpiresAt) {
		return errors.New("OTP has expired, please request a new one")
	}

	return repositories.MarkOTPUsed(input.Email, input.OTP)
}

func CheckSchoolIDService(input CheckSchoolIDInput) error {
	user, err := repositories.FindUserBySchoolID(input.SchoolID)
	if err == nil && user != nil {
		return errors.New("School ID already registered")
	}

	return nil
}

func GetSchoolsService() ([]model.School, error) {
	var schools []model.School
	result := database.DB.Find(&schools)
	if result.Error != nil {
		return nil, result.Error
	}
	return schools, nil
}

func RegisterUser(input RegisterUserInput) (*model.User, error) {

	hashedPassword, err := utils.HashPassword(input.Password)
	if err != nil {
		return nil, errors.New("Failed to process password")
	}

	user := &model.User{
		Role:          status.RoleStudent,
		FirstName:     input.FirstName,
		LastName:      input.LastName,
		Email:         input.Email,
		SchoolID:      input.SchoolID,
		Department:    input.Department,
		Program:       input.Program,
		Year:          input.Year,
		Status:        status.UserStatusPending,
		Password:      hashedPassword,
		SchoolIDImage: input.SchoolIDImage,
	}

	if err := repositories.CreateUser(user); err != nil {
		return nil, errors.New("Failed to create user")
	}

	return user, nil
}

func RegisterStaffService(input RegisterStaffInput) error {
	user, err := repositories.FindUserByEmail(input.Email)
	if err == nil && user != nil {
		return errors.New("Email already registered")
	}

	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return errors.New("Failed to generate secure random password")
	}
	tempPassword := fmt.Sprintf("%x", b)

	hashedPassword, err := utils.HashPassword(tempPassword)
	if err != nil {
		return errors.New("Failed to encrypt admin credentials")
	}

	adminID := fmt.Sprintf("ADM-%d", time.Now().Unix())

	staff := model.User{
		FirstName: input.FirstName,
		LastName:  input.LastName,
		Email:     input.Email,
		Password:  hashedPassword,
		Role:      "Staff",
		Status:    status.UserStatusActive,
		SchoolID:  adminID,
	}

	if err := repositories.CreateUser(&staff); err != nil {
		return errors.New("Failed to create staff")
	}

	if err := utils.SendAdminWelcomeEmail(staff.Email, staff.FirstName, tempPassword); err != nil {
		return errors.New("Failed to send welcome email")
	}
	return nil
}

func SigninUser(input SigninInput) (*model.User, error) {
	user, err := repositories.FindUserByEmailOrSchoolID(input.Identifier, input.Identifier)
	if err != nil {
		return nil, errors.New("Invalid credentials")
	}

	if !utils.CheckPasswordHash(input.Password, user.Password) {
		return nil, errors.New("Invalid credentials")
	}

	if user.Status == status.UserStatusPending {
		return nil, errors.New("Your account is not yet approved by the admin.")
	} else if user.Status == status.UserStatusLocked {
		return nil, errors.New("Your account has been locked, please contact the admin.")
	} else if user.Status != status.UserStatusActive {
		return nil, errors.New("Your account status is invalid, please contact the admin.")
	}

	return user, nil
}

func ForgotPasswordService(input ForgotPasswordInput) error {
	user, err := repositories.FindUserByEmailOrSchoolID(input.Identifier, input.Identifier)
	if err != nil {
		return nil
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return errors.New("Failed to generate token")
	}
	token := hex.EncodeToString(tokenBytes)

	reset := &model.PasswordReset{
		UserID:    user.ID,
		Token:     token,
		ExpiresAt: time.Now().Add(10 * time.Minute),
		Used:      false,
	}

	if err := repositories.CreatePasswordReset(reset); err != nil {
		return errors.New("Failed to create reset token")
	}

	if err := utils.SendResetEmail(user.Email, token); err != nil {
		return errors.New("Failed to send reset email")
	}

	return nil
}

func ResetPasswordService(input ResetPasswordInput) error {
	reset, err := repositories.FindPasswordResetByToken(input.Token)
	if err != nil {
		return errors.New("Invalid or expired reset link")
	}

	if time.Now().After(reset.ExpiresAt) {
		return errors.New("Reset link has expired, please request a new one")
	}

	if len(input.Password) < 8 {
		return errors.New("Password must be at least 8 characters")
	}

	hashedPassword, err := utils.HashPassword(input.Password)
	if err != nil {
		return errors.New("Failed to process password")
	}

	if err := repositories.UpdateUserPassword(reset.UserID, hashedPassword); err != nil {
		return errors.New("Failed to update password")
	}

	return repositories.MarkTokenUsed(input.Token)
}

func ChangePasswordService(userID uint, input ChangePasswordInput) error {
	var user model.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		return errors.New("user not found")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.CurrentPassword)); err != nil {
		return errors.New("Current password is incorrect")
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(input.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return errors.New("Failed to hash password")
	}

	if err := database.DB.Model(&user).Update("password", string(hashed)).Error; err != nil {
		return errors.New("Failed to update password")
	}

	return nil
}

func ChangeInformationService(input ChangeInformationInput) error {
	var count int64

	database.DB.
		Model(&model.InformationChangeRequest{}).
		Where("school_id = ? AND status = ?", input.School_ID, "Pending").
		Count(&count)

	if count > 0 {
		return errors.New("You already have a pending request.")
	}

	request := model.InformationChangeRequest{
		SchoolID:   input.School_ID,
		Email:      input.Email,
		Department: input.Department,
		Program:    input.Program,
		Year:       input.Year,
		Status:     "Pending",
	}

	return database.DB.Create(&request).Error
}

func UpdateUserStatusService(input UpdateUserStatusInput) error {
	allowed := map[string]bool{
		"Active":   true,
		"Locked":   true,
		"Pending":  true,
		"Archived": true,
	}
	if !allowed[input.Status] {
		return errors.New("invalid status value")
	}

	var user model.User
	if err := database.DB.Where("school_id = ?", input.SchoolID).First(&user).Error; err != nil {
		return errors.New("user not found")
	}

	user.Status = input.Status

	if err := database.DB.Save(&user).Error; err != nil {
		return errors.New("failed to update user status")
	}

	return nil
}

func ApproveUserService(schoolID string) error {
	var user model.User

	if err := database.DB.Where("school_id = ?", schoolID).First(&user).Error; err != nil {
		return errors.New("User not found")
	}

	user.Status = "Active"

	if err := database.DB.Save(&user).Error; err != nil {
		return errors.New("Failed to approve user")
	}

	if err := utils.SendStudentWelcomeEmail(user.Email, user.FirstName); err != nil {
		return errors.New("Failed to send approval email")
	}

	return nil
}

func RejectUserService(input ApproveRejectInput) error {
	var user model.User

	if err := database.DB.Where("school_id = ?", input.SchoolID).First(&user).Error; err != nil {
		return errors.New("User not found")
	}

	if err := utils.SendRegisterRejectionEmail(user.FirstName, user.Email, input.Reason); err != nil {
		return errors.New("Failed to send rejection email")
	}

	if err := database.DB.Unscoped().Delete(&user).Error; err != nil {
		return errors.New("Failed to delete user record")
	}
	return nil
}
