package services

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"SmartLib_Likod/model"
	"SmartLib_Likod/model/status"
	"SmartLib_Likod/repositories"
	"SmartLib_Likod/utils"
)

type RegisterInput struct {
	FirstName string `json:"firstname"`
	LastName  string `json:"lastname"`
	Email     string `json:"email"`
	SchoolID  string `json:"school_id"`
	Program   string `json:"program"`
	Year      string `json:"year"`
	Password  string `json:"password"`
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

func RegisterUser(input RegisterInput) (*model.User, error) {
	existing, err := repositories.FindUserByEmailOrSchoolID(input.Email, input.SchoolID)
	if err == nil && existing.ID != 0 {
		return nil, errors.New("Email or school ID already registered")
	}

	hashedPassword, err := utils.HashPassword(input.Password)
	if err != nil {
		return nil, errors.New("Failed to process password")
	}

	user := &model.User{
		FirstName: input.FirstName,
		LastName:  input.LastName,
		Email:     input.Email,
		SchoolID:  input.SchoolID,
		Program:   input.Program,
		Year:      input.Year,
		Status:    status.UserStatusNew,
		Password:  hashedPassword,
	}

	if err := repositories.CreateUser(user); err != nil {
		return nil, errors.New("Failed to create user")
	}

	return user, nil
}

func SigninUser(input SigninInput) (*model.User, error) {
	user, err := repositories.FindUserByEmailOrSchoolID(input.Identifier, input.Identifier)
	if err != nil {
		return nil, errors.New("Invalid credentials")
	}

	if !utils.CheckPasswordHash(input.Password, user.Password) {
		return nil, errors.New("Invalid credentials")
	}

	if user.Status == status.UserStatusNew {
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
