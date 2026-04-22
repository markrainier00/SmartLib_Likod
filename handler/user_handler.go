package handler

import (
	"SmartLib_Likod/database"
	"SmartLib_Likod/model"

	"github.com/gofiber/fiber/v2"
)

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
