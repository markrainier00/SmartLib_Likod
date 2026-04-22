package handler

import (
	"fmt"
	"time"

	"SmartLib_Likod/database"
	"SmartLib_Likod/model"
	errormodel "SmartLib_Likod/model/error"
	"SmartLib_Likod/model/response"
	"SmartLib_Likod/model/status"
	"SmartLib_Likod/repositories"
	"SmartLib_Likod/services"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

func GetUserBorrowRequestHandler(c *fiber.Ctx) error {
	schoolID := c.Params("school_id")

	var transaction []model.Transaction
	if err := database.DB.Where("school_id = ?", schoolID).
		Order("created_at desc").
		Find(&transaction).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Failed to fetch book borrow requests.",
		})
	}

	return c.JSON(fiber.Map{
		"isSuccess": true,
		"data":      transaction,
	})
}

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

	// ==========================================
	// 🔔 MGA TRIGGERS PARA SA NOTIFICATION
	// ==========================================

	// 1. Notif para sa Student (Papasok sa history nila)
	msg := fmt.Sprintf("Your book request for ISBN %s has been submitted.", input.ISBN)
	sendStudentNotification(input.SchoolID, msg)

	// 2. Real-time Notif para sa ADMIN at STAFF (Ito ang magpapatunog ng bell ni Mark)
	adminMsg := fmt.Sprintf("New Book Request: Student %s is requesting ISBN %s. Review now.", input.SchoolID, input.ISBN)
	services.BroadcastToRole("Admin", adminMsg)
	services.BroadcastToRole("Staff", adminMsg)

	return c.Status(fiber.StatusCreated).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Book request saved successfully",
		Data:    nil,
	})
}

func AddWishlistHandler(c *fiber.Ctx) error {
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

func RemoveWishlistHandler(c *fiber.Ctx) error {
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

func GetUserWishlistHandler(c *fiber.Ctx) error {
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

func GetBookBorrowRequestHandler(c *fiber.Ctx) error {
	var transaction []model.Transaction
	if err := database.DB.Where("status = ?", "Pending").
		Order("created_at desc").
		Find(&transaction).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Failed to fetch book borrow requests.",
		})
	}

	return c.JSON(fiber.Map{
		"isSuccess": true,
		"data":      transaction,
	})
}

func GetActiveBorrowHandler(c *fiber.Ctx) error {
	var transaction []model.Transaction
	if err := database.DB.Where("status = ?", "Borrowed").
		Order("created_at desc").
		Find(&transaction).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Failed to fetch book borrow requests.",
		})
	}

	return c.JSON(fiber.Map{
		"isSuccess": true,
		"data":      transaction,
	})
}

func ApproveRequestHandler(c *fiber.Ctx) error {
	id := c.Params("id")
	isbn := c.Params("isbn")

	var transaction model.Transaction
	var book model.Book

	if err := database.DB.First(&transaction, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Request not found.",
		})
	}
	if err := database.DB.Where("isbn = ?", isbn).First(&book).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Book not found.",
		})
	}
	if book.Available <= 0 {
		return c.Status(400).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "No copies available",
		})
	}

	book.Available -= 1
	transaction.Status = "Approved"
	transaction.ApproveDate = time.Now()

	if err := database.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Save(&transaction).Error; err != nil {
			return err
		}
		if err := tx.Save(&book).Error; err != nil {
			return err
		}
		return nil
	}); err != nil {
		return c.Status(500).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Failed to approve book borrow request",
		})
	}

	// 🔔 TRIGGER: Notif para sa Student kapag na-approve
	msg := fmt.Sprintf("Your request to borrow book (ISBN: %s) has been APPROVED!", isbn)
	sendStudentNotification(transaction.SchoolID, msg)

	return c.Status(200).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Book borrow request approved",
	})
}

func RejectRequestHandler(c *fiber.Ctx) error {
	id := c.Params("id")
	var transaction model.Transaction

	if err := database.DB.First(&transaction, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Request not found.",
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

	transaction.RejectReason = c.FormValue("reject_reason")
	transaction.Status = "Rejected"
	transaction.RejectDate = time.Now()

	result := database.DB.Save(&transaction)
	if result.Error != nil {
		return c.Status(500).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Failed to process book borrow request rejection.",
		})
	}

	// 🔔 TRIGGER: Notif para sa Student kapag na-reject
	msg := fmt.Sprintf("Your book request was REJECTED. Reason: %s", transaction.RejectReason)
	sendStudentNotification(transaction.SchoolID, msg)

	return c.Status(200).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Book borrow request rejected.",
	})
}

func GetAllTransactions(c *fiber.Ctx) error {
	var transactions []model.Transaction

	if err := database.DB.Order("created_at asc").Find(&transactions).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"isSuccess": false, "message": "Failed to fetch transactions"})
	}

	return c.JSON(fiber.Map{"isSuccess": true, "data": transactions})
}

func ReturnBookHandler(c *fiber.Ctx) error {
	id := c.Params("id")

	var transaction model.Transaction
	if err := database.DB.First(&transaction, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Borrow not found.",
		})
	}

	var user model.User
	if err := database.DB.Where("school_id = ?", transaction.SchoolID).First(&user).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "User not found.",
		})
	}

	var input struct {
		Violation      string `json:"violation"`
		ViolationCount int    `json:"violation_count"`
		OverduePoint   int    `json:"overdue_point"`
	}
	if err := c.BodyParser(&input); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Invalid input data",
		})
	}

	if input.ViolationCount < 0 || input.OverduePoint < 0 {
		return c.Status(400).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "violation_count must be a valid number",
		})
	}

	user.ViolationCount += input.ViolationCount
	if input.ViolationCount > 0 {
		user.OffenseCount += 1
	}
	transaction.Violation = input.Violation
	if input.OverduePoint < 1 {
		transaction.Status = "Returned"
	} else {
		transaction.Status = "Returned Late"
	}
	transaction.DateReturned = time.Now()

	tx := database.DB.Begin()
	if err := tx.Save(&user).Error; err != nil {
		tx.Rollback()
		return c.Status(500).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Failed to process book borrow request rejection.",
		})
	}
	if err := tx.Save(&transaction).Error; err != nil {
		tx.Rollback()
		return c.Status(500).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Failed to process book borrow request rejection.",
		})
	}
	tx.Commit()

	// 🔔 TRIGGER: Notif para sa Student kapag naibalik na ang libro
	msg := "Your book has been marked as RETURNED."
	if input.OverduePoint > 0 {
		msg += " Note: Returned late."
	}
	sendStudentNotification(transaction.SchoolID, msg)

	return c.Status(200).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Book marked as returned.",
	})
}

// ==========================================
// 🚀 HELPER FUNCTION PARA SA NOTIFICATIONS
// ==========================================

func sendStudentNotification(schoolID string, message string) {
	// 1. I-save sa database
	notif := &model.Notification{
		SchoolID: schoolID,
		Message:  message,
		IsRead:   false,
	}
	database.DB.Create(notif)

	// 2. I-send nang live sa React frontend
	payload := services.NotificationPayload{
		ID:   int64(notif.ID),
		Msg:  message,
		Time: time.Now().Format("Jan 02, 3:04 PM"),
		Read: false,
	}
	services.NotifHub.SendNotification(schoolID, payload)
}
