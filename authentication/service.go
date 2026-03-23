package services

import (
	"SmartLib_Likod/model"
	"SmartLib_Likod/model/status"
	"SmartLib_Likod/repositories" // DITO NAKATIRA YUNG MGA FIND AT CREATE FUNCTIONS
	"SmartLib_Likod/utils"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"
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
	// Dinagdagan natin ng repositories. sa unahan para mahanap ni Go
	existing, err := repositories.FindUserByEmailOrSchoolID(input.Email, input.SchoolID)
	if err == nil && existing.ID != 0 {
		return nil, errors.New("email or school ID already registered")
	}

	hashedPassword, err := utils.HashPassword(input.Password)
	if err != nil {
		return nil, errors.New("failed to process password")
	}

	user := &model.User{
		FirstName: input.FirstName,
		LastName:  input.LastName,
		Email:     input.Email,
		SchoolID:  input.SchoolID,
		Program:   input.Program,
		Year:      input.Year,
		Status:    status.UserStatusPending,
		Password:  hashedPassword,
	}

	if err := repositories.CreateUser(user); err != nil {
		return nil, errors.New("failed to create user")
	}

	return user, nil
}

func SigninUser(input SigninInput) (*model.User, error) {
	user, err := repositories.FindUserByEmailOrSchoolID(input.Identifier, input.Identifier)
	if err != nil {
		return nil, errors.New("invalid credentials")
	}

	if !utils.CheckPasswordHash(input.Password, user.Password) {
		return nil, errors.New("invalid credentials")
	}

	if user.Status == status.UserStatusPending {
		return nil, errors.New("your account is not yet approved by the admin")
	} else if user.Status == status.UserStatusLocked {
		return nil, errors.New("your account has been locked, please contact the admin")
	} else if user.Status != status.UserStatusActive {
		return nil, errors.New("your account status is invalid, please contact the admin")
	}

	return user, nil
}

func ForgotPasswordService(input ForgotPasswordInput) error {
	user, err := repositories.FindUserByEmailOrSchoolID(input.Identifier, input.Identifier)
	if err != nil {
		return nil // Quiet fail for security
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return errors.New("failed to generate token")
	}
	token := hex.EncodeToString(tokenBytes)

	reset := &model.PasswordReset{
		UserID:    user.ID,
		Token:     token,
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Used:      false,
	}

	if err := repositories.CreatePasswordReset(reset); err != nil {
		return errors.New("failed to create reset token")
	}

	if err := utils.SendResetEmail(user.Email, token); err != nil {
		return errors.New("failed to send reset email")
	}

	return nil
}

func ResetPasswordService(input ResetPasswordInput) error {
	reset, err := repositories.FindPasswordResetByToken(input.Token)
	if err != nil {
		return errors.New("invalid or expired reset link")
	}

	if time.Now().After(reset.ExpiresAt) {
		return errors.New("reset link has expired, please request a new one")
	}

	if len(input.Password) < 8 {
		return errors.New("password must be at least 8 characters")
	}

	hashedPassword, err := utils.HashPassword(input.Password)
	if err != nil {
		return errors.New("failed to process password")
	}

	if err := repositories.UpdateUserPassword(reset.UserID, hashedPassword); err != nil {
		return errors.New("failed to update password")
	}

	return repositories.MarkTokenUsed(input.Token)
}
