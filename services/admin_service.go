package services

import (
	"SmartLib_Likod/database"
	"SmartLib_Likod/model"
	"SmartLib_Likod/model/status"
	"SmartLib_Likod/repositories"
	"SmartLib_Likod/utils"
	"crypto/rand"
	"errors"
	"fmt"
	"time"
)

// CreateAdminInput - Structure ng request mula sa frontend
type CreateAdminInput struct {
	FirstName string `json:"firstname"`
	LastName  string `json:"lastname"`
	Email     string `json:"email"`
	Role      string `json:"role"` // Halimbawa: "Assistant Librarian"
}

// CreateAdminAccountService - Logic para sa paggawa ng admin at pag-send ng email
func CreateAdminAccountService(input CreateAdminInput) error {
	// 1. GENERATE RANDOM PASSWORD (Hex Format)
	// Ang 4 bytes ay laging magbibigay ng 8 characters sa hex format.
	// Hinding-hindi ito mag-cacause ng "out of range" error (no slicing).
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return errors.New("failed to generate secure random password")
	}
	tempPassword := fmt.Sprintf("%x", b) // Halimbawa: "e4f1a2b3"

	// 2. HASH THE PASSWORD (Para sa database)
	hashedPassword, err := utils.HashPassword(tempPassword)
	if err != nil {
		return errors.New("failed to encrypt admin credentials")
	}

	// 3. PREPARE ADMIN MODEL
	// SchoolID format: ADM-1710928374 (Timestamp based)
	adminID := fmt.Sprintf("ADM-%d", time.Now().Unix())

	newAdmin := model.User{
		FirstName: input.FirstName,
		LastName:  input.LastName,
		Email:     input.Email,
		Password:  hashedPassword,
		Role:      "admin",                 // System access level
		Status:    status.UserStatusActive, // Auto-active ang admin accounts
		SchoolID:  adminID,
		Program:   input.Role, // Nilalagay ang position/role sa program field
	}

	// 4. SAVE TO DATABASE
	// Siguraduhin na ang repositories.CreateUser ay gumagana nang tama
	if err := repositories.CreateUser(&newAdmin); err != nil {
		return errors.New("failed to save admin account to the database")
	}

	// 5. SEND WELCOME EMAIL (Background Process)
	// Ginagamitan natin ng 'go routine' para hindi mag-antay ang React frontend.
	// Mag-su-success agad ang UI, habang sinesend ang email sa likod.
	fmt.Printf("🚀 Admin Created: %s | Temp Pass: %s\n", input.Email, tempPassword)

	go func(email, name, pass string) {
		errEmail := utils.SendAdminWelcomeEmail(email, name, pass)
		if errEmail != nil {
			fmt.Printf("❌ Email Error for %s: %v\n", email, errEmail)
		} else {
			fmt.Printf("✅ Welcome email sent successfully to %s\n", email)
		}
	}(input.Email, input.FirstName, tempPassword)

	return nil
}

func ApproveInformationRequest(id uint) error {
	var req model.InformationChangeRequest

	if err := database.DB.First(&req, id).Error; err != nil {
		return err
	}

	err := database.DB.Model(&model.User{}).
		Where("school_id = ?", req.SchoolID).
		Updates(map[string]interface{}{
			"email":      req.Email,
			"department": req.Department,
			"program":    req.Program,
			"year":       req.Year,
		}).Error

	if err != nil {
		return err
	}

	return database.DB.Model(&req).
		Update("status", "Approved").Error
}

func RejectInformationRequest(id uint, reason string) error {
	return database.DB.Model(&model.InformationChangeRequest{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"status":        "Rejected",
			"reject_reason": reason,
		}).Error
}
