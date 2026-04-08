package handler

import (
	errormodel "SmartLib_Likod/model/error"
	"SmartLib_Likod/model/response"
	"SmartLib_Likod/model/status"
	"SmartLib_Likod/services"
	"time"

	"SmartLib_Likod/database"
	"SmartLib_Likod/model"
	"SmartLib_Likod/repositories"

	"github.com/gofiber/fiber/v2"
)

func RequestBook(c *fiber.Ctx) error {
	var input services.RequestInput

	if err := c.BodyParser(&input); err != nil {
		return c.Status(400).JSON(errormodel.ErrorModel{
			Message:   status.RetCode404,
			IsSuccess: false,
			Error:     err,
		})
	}

	count, err := repositories.HasActiveRequest(input.SchoolID, input.ISBN)
	if err != nil {
		return c.Status(500).JSON(errormodel.ErrorModel{
			Message:   "Database error",
			IsSuccess: false,
			Error:     err,
		})
	}

	if count > 0 {
		return c.Status(400).JSON(errormodel.ErrorModel{
			Message:   "You already have an active request for this book",
			IsSuccess: false,
		})
	}

	if err := services.RequestBookService(input); err != nil {
		return c.Status(400).JSON(errormodel.ErrorModel{
			Message:   err.Error(),
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.Status(fiber.StatusCreated).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Book request saved successfully",
		Data:    nil,
	})
}

// func BorrowBook(c *fiber.Ctx) error {
// 	var input services.BorrowInput
// 	if err := c.BodyParser(&input); err != nil {
// 		return c.Status(400).JSON(fiber.Map{"message": "Invalid input format", "isSuccess": false})
// 	}

// 	if err := services.BorrowBookService(input); err != nil {
// 		return c.Status(400).JSON(fiber.Map{"message": err.Error(), "isSuccess": false})
// 	}

// 	return c.Status(201).JSON(fiber.Map{"message": "Request sent to Staff!", "isSuccess": true})
// }

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

func AddWishlist(c *fiber.Ctx) error {
	var input services.WishlistInput

	if err := c.BodyParser(&input); err != nil {
		return c.Status(400).JSON(errormodel.ErrorModel{
			Message:   status.RetCode404,
			IsSuccess: false,
			Error:     err,
		})
	}

	if err := services.AddWishlistService(input); err != nil {
		return c.Status(400).JSON(errormodel.ErrorModel{
			Message:   err.Error(),
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Added to wishlist",
	})
}

func RemoveWishlist(c *fiber.Ctx) error {
	var input services.WishlistInput

	if err := c.BodyParser(&input); err != nil {
		return c.Status(400).JSON(errormodel.ErrorModel{
			Message:   status.RetCode404,
			IsSuccess: false,
			Error:     err,
		})
	}

	if err := services.RemoveWishlistService(input); err != nil {
		return c.Status(400).JSON(errormodel.ErrorModel{
			Message:   err.Error(),
			IsSuccess: false,
			Error:     err,
		})
	}

	return c.JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Removed from wishlist",
	})
}

func GetWishlist(c *fiber.Ctx) error {
	schoolID := c.Params("school_id")

	var wishlist []model.Wishlist
	if err := database.DB.Where("school_id = ?", schoolID).Find(&wishlist).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Failed to fetch wishlist",
		})
	}

	bookIDs := make([]string, len(wishlist))
	for i, w := range wishlist {
		bookIDs[i] = w.ISBN
	}

	return c.JSON(fiber.Map{
		"isSuccess": true,
		"data":      bookIDs,
	})
}

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

func RejectBookHandler(c *fiber.Ctx) error {
	id := c.Params("id")
	var transaction model.Transaction

	if err := database.DB.First(&transaction, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Book not found.",
		})
	}

	var input struct {
		RejectReason string `json:"reject_reason"`
	}
	if err := c.BodyParser(&input); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Invalid input data",
		})
	}

	transaction.RejectReason = input.RejectReason
	transaction.Status = "Rejected"
	transaction.RejectDate = time.Now()

	result := database.DB.Save(&transaction)
	if result.Error != nil {
		return c.Status(500).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Failed to update book",
		})
	}

	return c.JSON(fiber.Map{"isSuccess": true, "message": "Request rejected successfully"})
}

func GetAllTransactions(c *fiber.Ctx) error {
	var transactions []model.Transaction

	// Kunin lahat ng transactions sa database, pinakabago muna
	if err := database.DB.Order("created_at desc").Find(&transactions).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"isSuccess": false, "message": "Failed to fetch transactions"})
	}

	return c.JSON(fiber.Map{"isSuccess": true, "data": transactions})
}

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
