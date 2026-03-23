package handler

import (
	"SmartLib_Likod/database"
	"SmartLib_Likod/model"
	errormodel "SmartLib_Likod/model/error"
	"SmartLib_Likod/model/response"
	"SmartLib_Likod/model/status"
	"SmartLib_Likod/repositories"
	"SmartLib_Likod/services"
	"SmartLib_Likod/utils"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
)

// GetAllRegistrations - Ibinibigay sa Admin ang listahan ng mga users na "New" (Pending)
func GetAllRegistrations(c *fiber.Ctx) error {
	users, err := repositories.GetAllRegistrations()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"isSuccess": false, "message": "Failed to fetch registrations"})
	}
	return c.JSON(fiber.Map{"isSuccess": true, "data": users})
}

// ApproveUser - Gagawing "Active" ang status ng student
func ApproveUser(c *fiber.Ctx) error {
	type Req struct {
		SchoolID string `json:"school_id"`
	}
	var body Req
	if err := c.BodyParser(&body); err != nil {
		return c.Status(400).JSON(fiber.Map{"isSuccess": false, "message": "Invalid request"})
	}

	// I-update sa database (Status: Active, RejectReason: blanko)
	err := repositories.UpdateUserStatus(body.SchoolID, "Active", "")
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"isSuccess": false, "message": "Failed to approve user"})
	}
	return c.JSON(fiber.Map{"isSuccess": true, "message": "User approved successfully"})
}

// RejectUser - Gagawing "Rejected" ang status at isasave ang dahilan
func RejectUser(c *fiber.Ctx) error {
	type Req struct {
		SchoolID string `json:"school_id"`
		Reason   string `json:"reason"`
	}
	var body Req
	if err := c.BodyParser(&body); err != nil {
		return c.Status(400).JSON(fiber.Map{"isSuccess": false, "message": "Invalid request"})
	}

	// I-update sa database (Status: Rejected, RejectReason: body.Reason)
	err := repositories.UpdateUserStatus(body.SchoolID, "Rejected", body.Reason)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"isSuccess": false, "message": "Failed to reject user"})
	}
	return c.JSON(fiber.Map{"isSuccess": true, "message": "User rejected successfully"})
}

// ==========================================
// 🚀 MANAGE ACCOUNTS (LOCK/UNLOCK & DELETE)
// ==========================================

// ChangeAccountStatus - Handles Lock and Unlock actions
func ChangeAccountStatus(c *fiber.Ctx) error {
	type Req struct {
		SchoolID string `json:"school_id"`
		Status   string `json:"status"` // "Locked" or "Active"
	}
	var body Req
	if err := c.BodyParser(&body); err != nil {
		return c.Status(400).JSON(fiber.Map{"isSuccess": false, "message": "Invalid request"})
	}

	err := repositories.UpdateAccountStatus(body.SchoolID, body.Status)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"isSuccess": false, "message": "Failed to update account status"})
	}
	return c.JSON(fiber.Map{"isSuccess": true, "message": "Account status updated successfully"})
}

// DeleteAccount - Permanently deletes a user from the system
func DeleteAccount(c *fiber.Ctx) error {
	schoolID := c.Params("id") // Halimbawa: /api/users/2024-0001

	err := repositories.DeleteUserBySchoolID(schoolID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"isSuccess": false, "message": "Failed to delete account"})
	}
	return c.JSON(fiber.Map{"isSuccess": true, "message": "Account deleted successfully"})
}

// ==========================================
// 🚀 SUPER ADMIN: GET ALL ACCOUNTS
// ==========================================
func GetAllAccounts(c *fiber.Ctx) error {
	var users []model.User

	// Kukunin natin lahat ng users sa database para sa Accounts Page
	if err := database.DB.Find(&users).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Failed to fetch accounts",
		})
	}

	return c.JSON(fiber.Map{
		"isSuccess": true,
		"data":      users,
	})
}

// ==========================================
// 🚀 SUPER ADMIN: CREATE ADMIN ACCOUNT
// ==========================================
type CreateAdminInput struct {
	FirstName string `json:"firstname"`
	LastName  string `json:"lastname"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	Role      string `json:"role"` // Library Admin, Assistant Admin, etc. (Display purpose)
}

func CreateAdminAccount(c *fiber.Ctx) error {
	var input CreateAdminInput

	if err := c.BodyParser(&input); err != nil {
		return c.Status(400).JSON(fiber.Map{"isSuccess": false, "message": "Invalid input"})
	}

	// 1. I-check kung may kaparehong email na
	var existing model.User
	if err := database.DB.Where("email = ?", input.Email).First(&existing).Error; err == nil {
		return c.Status(400).JSON(fiber.Map{"isSuccess": false, "message": "Email is already registered"})
	}

	// 2. I-Hash ang password para secure!
	hashedPassword, err := utils.HashPassword(input.Password)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"isSuccess": false, "message": "Failed to encrypt password"})
	}

	// 🚀 3. Gumawa ng Unique Admin ID! (Hal. ADMIN-1710928374)
	uniqueAdminID := fmt.Sprintf("ADMIN-%d", time.Now().Unix())

	// 4. I-save sa Supabase bilang ADMIN at ACTIVE agad
	newAdmin := model.User{
		FirstName: input.FirstName,
		LastName:  input.LastName,
		Email:     input.Email,
		Password:  hashedPassword,
		SchoolID:  uniqueAdminID, // 👈 Hindi na "N/A"
		Program:   input.Role,
		Year:      "N/A",
		Status:    "Active",
		Role:      "admin",
	}

	if err := database.DB.Create(&newAdmin).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"isSuccess": false, "message": "Failed to create admin account"})
	}

	return c.JSON(fiber.Map{
		"isSuccess": true,
		"message":   "Admin account successfully created!",
	})
}

func GetStudentHistory(c *fiber.Ctx) error {
	schoolID := c.Query("school_id")

	if schoolID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode401,
			IsSuccess: false,
			Error:     nil,
		})
	}

	history, err := services.GetStudentHistoryService(schoolID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
			Message:   "Failed to fetch student history",
			IsSuccess: false,
			Error:     err,
		})
	}
	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Student history fetched successfully",
		Data:    history,
	})
}
