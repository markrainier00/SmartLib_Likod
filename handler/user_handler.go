package handler

import (
	"SmartLib_Likod/database"
	"SmartLib_Likod/model"
	"SmartLib_Likod/repositories"
	"SmartLib_Likod/services"

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

	err := repositories.UpdateUserStatus(body.SchoolID, "Rejected", body.Reason)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"isSuccess": false, "message": "Failed to reject user"})
	}
	return c.JSON(fiber.Map{"isSuccess": true, "message": "User rejected successfully"})
}

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
	schoolID := c.Params("id")

	err := repositories.DeleteUserBySchoolID(schoolID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"isSuccess": false, "message": "Failed to delete account"})
	}
	return c.JSON(fiber.Map{"isSuccess": true, "message": "Account deleted successfully"})
}

// GetAllAccounts - Super Admin: Kukunin lahat ng users
func GetAllAccounts(c *fiber.Ctx) error {
	var users []model.User
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
// 🚀 SUPER ADMIN: CREATE ADMIN ACCOUNT (UPDATED)
// ==========================================

func CreateAdminAccount(c *fiber.Ctx) error {
	// Ginagamit natin ang Input struct mula sa services para consistent
	var input services.CreateAdminInput

	if err := c.BodyParser(&input); err != nil {
		return c.Status(400).JSON(fiber.Map{"isSuccess": false, "message": "Invalid input"})
	}

	// 1. Validation: I-check kung existing na ang email
	var existing model.User
	if err := database.DB.Where("email = ?", input.Email).First(&existing).Error; err == nil {
		return c.Status(400).JSON(fiber.Map{"isSuccess": false, "message": "Email is already registered"})
	}

	// 2. Tawagin ang Service
	// Ang service na ang bahala sa: Random Password -> Hashing -> DB Save -> Send Email
	if err := services.CreateAdminAccountService(input); err != nil {
		return c.Status(500).JSON(fiber.Map{
			"isSuccess": false,
			"message":   err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"isSuccess": true,
		"message":   "Admin account created. Temporary password sent to email!",
	})
}
