package handler

import (
	"SmartLib_Likod/database"
	"SmartLib_Likod/model"

	"github.com/gofiber/fiber/v2"
)

// GetStudentScannerData - Kinukuha ang data ng student pagka-scan ng QR
func GetStudentScannerData(c *fiber.Ctx) error {
	schoolID := c.Params("school_id") // Kukunin ang ID mula sa URL (e.g., /api/scanner/2024-00123)

	// 🚀 1. Hanapin ang Estudyante (Mula sa User model)
	var user model.User
	if err := database.DB.Where("school_id = ?", schoolID).First(&user).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Student record not found or not registered.",
		})
	}

	// 🚀 2. Hanapin ang mga Pending Books (Mula sa Transaction model)
	var transactions []model.Transaction
	database.DB.Where("school_id = ? AND status = ?", schoolID, "Pending").Find(&transactions)

	// I-extract ang mga title ng libro para madaling basahin ng Next.js
	var pendingBooks []string
	for _, t := range transactions {
		pendingBooks = append(pendingBooks, t.BookTitle)
	}

	// 🚀 3. Kwentahin ang Unpaid Penalties (Mula sa Penalty model)
	var penalties []model.Penalty
	database.DB.Where("school_id = ? AND is_paid = ?", schoolID, false).Find(&penalties)

	var totalPenalty float64 = 0
	for _, p := range penalties {
		totalPenalty += p.Amount
	}

	// 🚀 4. Ipadala ang pinagsama-samang data pabalik sa Scanner UI
	return c.JSON(fiber.Map{
		"isSuccess": true,
		"data": fiber.Map{
			"school_id":     user.SchoolID,
			"student_name":  user.FirstName + " " + user.LastName, // Pinagdikit natin ang First at Last name
			"pending_books": pendingBooks,
			"penalty":       totalPenalty,
		},
	})
}
