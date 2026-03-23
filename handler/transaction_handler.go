package handler

import (
	errormodel "SmartLib_Likod/model/error"
	"SmartLib_Likod/model/response"

	// "SmartLib_Likod/model/status"
	"SmartLib_Likod/database" // 🚀 IDINAGDAG: Para makapag-query tayo direkta sa database
	"SmartLib_Likod/model"    // 🚀 IDINAGDAG: Para sa Transaction model natin
	"SmartLib_Likod/repositories"
	"SmartLib_Likod/services"

	"github.com/gofiber/fiber/v2"
)

func BorrowBook(c *fiber.Ctx) error {
	var input services.BorrowInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(400).JSON(fiber.Map{"message": "Invalid input format", "isSuccess": false})
	}

	if err := services.BorrowBookService(input); err != nil {
		return c.Status(400).JSON(fiber.Map{"message": err.Error(), "isSuccess": false})
	}

	return c.Status(201).JSON(fiber.Map{"message": "Request sent to Staff!", "isSuccess": true})
}

func GetAllRequests(c *fiber.Ctx) error {
	requests, err := services.GetAllRequestsService()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
			Message:   "Failed to fetch requests",
			IsSuccess: false,
			Error:     err,
		})
	}
	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Requests fetched successfully",
		Data:    requests,
	})
}

// ==========================================
// 🚀 IN-UPDATE: APPROVE / RELEASE BOOK
// ==========================================
func ReleaseBook(c *fiber.Ctx) error {
	type Req struct {
		SchoolID      string `json:"school_id"`
		TransactionID uint   `json:"transaction_id"` // Sasaluhin natin yung ID galing sa React
	}
	var body Req
	if err := c.BodyParser(&body); err != nil {
		return c.Status(400).JSON(fiber.Map{"message": "Invalid request", "isSuccess": false})
	}

	// 1. Kung galing sa bagong React Admin Dashboard (Gamit ang Transaction ID)
	if body.TransactionID != 0 {
		var tx model.Transaction
		if err := database.DB.First(&tx, body.TransactionID).Error; err != nil {
			return c.Status(404).JSON(fiber.Map{"isSuccess": false, "message": "Transaction not found"})
		}
		tx.Status = "Approved" // Ise-set natin as Approved
		database.DB.Save(&tx)
		return c.JSON(fiber.Map{"message": "Request approved!", "isSuccess": true})
	}

	// 2. Fallback sa lumang logic mo (Kung School ID ang ipinasa)
	if err := services.ReleaseBookService(body.SchoolID); err != nil {
		return c.Status(500).JSON(fiber.Map{"message": err.Error(), "isSuccess": false})
	}
	return c.JSON(fiber.Map{"message": "Book released!", "isSuccess": true})
}

// ==========================================
// 🚀 IN-UPDATE: REJECT BOOK
// ==========================================
func RejectBook(c *fiber.Ctx) error {
	type Req struct {
		SchoolID      string `json:"school_id"`
		TransactionID uint   `json:"transaction_id"` // Sasaluhin natin yung ID galing sa React
		Reason        string `json:"reason"`         // Sasaluhin natin yung dahilan ng pag-reject
	}
	var body Req
	if err := c.BodyParser(&body); err != nil {
		return c.Status(400).JSON(fiber.Map{"message": "Invalid request", "isSuccess": false})
	}

	// 1. Kung galing sa bagong React Admin Dashboard
	if body.TransactionID != 0 {
		var tx model.Transaction
		if err := database.DB.First(&tx, body.TransactionID).Error; err != nil {
			return c.Status(404).JSON(fiber.Map{"isSuccess": false, "message": "Transaction not found"})
		}
		tx.Status = "Rejected"
		// Pwede nating i-save ang reason kung may column ka na 'RejectReason' sa database mo.
		database.DB.Save(&tx)
		return c.JSON(fiber.Map{"isSuccess": true, "message": "Request rejected successfully"})
	}

	// 2. Fallback sa lumang logic mo
	err := repositories.UpdateTransactionStatus(body.SchoolID, "Pending", "Rejected")
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"message": "Failed to reject request", "isSuccess": false})
	}
	return c.JSON(fiber.Map{"isSuccess": true, "message": "Request rejected successfully"})
}

// ==========================================
// 🚀 BAGONG DAGDAG: GET ALL TRANSACTIONS (Ito ang hinahanap ng React!)
// ==========================================
func GetAllTransactions(c *fiber.Ctx) error {
	var transactions []model.Transaction

	// Kunin lahat ng transactions sa database, pinakabago muna
	if err := database.DB.Order("created_at desc").Find(&transactions).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"isSuccess": false, "message": "Failed to fetch transactions"})
	}

	return c.JSON(fiber.Map{"isSuccess": true, "data": transactions})
}

// ==========================================
// 🚀 BAGONG DAGDAG: MARK AS RETURNED
// ==========================================
func ReturnBook(c *fiber.Ctx) error {
	type Req struct {
		TransactionID uint `json:"transaction_id"`
	}
	var body Req
	if err := c.BodyParser(&body); err != nil {
		return c.Status(400).JSON(fiber.Map{"isSuccess": false, "message": "Invalid input"})
	}

	var tx model.Transaction
	if err := database.DB.First(&tx, body.TransactionID).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"isSuccess": false, "message": "Transaction not found"})
	}

	tx.Status = "Returned" // Papalitan ang status ng libro sa Returned

	if err := database.DB.Save(&tx).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"isSuccess": false, "message": "Failed to update database"})
	}

	return c.JSON(fiber.Map{"isSuccess": true, "message": "Book returned successfully"})
}
