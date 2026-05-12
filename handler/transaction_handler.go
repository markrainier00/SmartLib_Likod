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
	"SmartLib_Likod/utils"

	"github.com/gofiber/fiber/v2"
)

func GetUserBorrowRequestHandler(c *fiber.Ctx) error {
	schoolID := c.Params("school_id")

	var transaction []model.Transaction
	if err := database.DB.Where("school_id = ? AND status = ?", schoolID, "Pending").
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

	request, err := repositories.HasActiveRequest(input.SchoolID, input.ISBN)
	if err != nil {
		return c.Status(500).JSON(errormodel.ErrorModel{
			Message:   "Database error",
			IsSuccess: false,
			Error:     err,
		})
	}

	if request > 0 {
		return c.Status(400).JSON(errormodel.ErrorModel{
			Message:   "You already have an active request for this book",
			IsSuccess: false,
		})
	}

	borrow, err := repositories.HasActiveBorrow(input.SchoolID, input.ISBN)
	if err != nil {
		return c.Status(500).JSON(errormodel.ErrorModel{
			Message:   "Database error",
			IsSuccess: false,
			Error:     err,
		})
	}

	if borrow > 0 {
		return c.Status(400).JSON(errormodel.ErrorModel{
			Message:   "You already have an active borrow for this book",
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

func CancelRequestHandler(c *fiber.Ctx) error {
	var input struct {
		ID uint `json:"id"`
	}

	if err := c.BodyParser(&input); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Invalid input",
		})
	}

	if input.ID == 0 {
		return c.Status(400).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "ID is required",
		})
	}

	if err := services.CancelRequestService(input.ID); err != nil {
		return c.Status(500).JSON(fiber.Map{
			"isSuccess": false,
			"message":   err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"isSuccess": true,
		"message":   "Request cancelled successfully",
	})
}

func AddWishlistHandler(c *fiber.Ctx) error {
	var input services.Wishlist

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
	var input services.Wishlist

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

func ToggleWishlistNotifyHandler(c *fiber.Ctx) error {
	var input struct {
		SchoolID string `json:"school_id"`
		ISBN     string `json:"isbn"`
	}

	if err := c.BodyParser(&input); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Invalid input",
		})
	}

	if err := services.ToggleWishlistNotify(input.SchoolID, input.ISBN); err != nil {
		return c.Status(500).JSON(fiber.Map{
			"isSuccess": false,
			"message":   err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"isSuccess": true,
		"message":   "Wishlist notify toggled",
	})
}

func GetUserWishlistHandler(c *fiber.Ctx) error {
	schoolID := c.Params("school_id")

	data, err := services.GetUserWishlistService(schoolID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Failed to fetch wishlist",
		})
	}

	return c.JSON(fiber.Map{
		"isSuccess": true,
		"data":      data,
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
			"message":   "Failed to fetch book borrows.",
		})
	}

	return c.JSON(fiber.Map{
		"isSuccess": true,
		"data":      transaction,
	})
}

func GetApprovedRequestsHandler(c *fiber.Ctx) error {
	var transaction []model.Transaction
	if err := database.DB.Where("status = ?", "Approved").
		Order("created_at desc").
		Find(&transaction).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Failed to fetch approved book borrow.",
		})
	}

	return c.JSON(fiber.Map{
		"isSuccess": true,
		"data":      transaction,
	})
}

func ApproveBorrowRequestHandler(c *fiber.Ctx) error {
	var input services.ApproveBorrowRequestInput

	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode404,
			IsSuccess: false,
			Error:     err,
		})
	}

	if input.TransactionID == 0 || input.ISBN == "" || input.Staff == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode401,
			IsSuccess: false,
			Error:     nil,
		})
	}

	if err := services.ApproveBorrowRequestService(input); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
			Message:   err.Error(),
			IsSuccess: false,
			Error:     err,
		})
	}

	var tx model.Transaction
	if err := database.DB.First(&tx, input.TransactionID).Error; err == nil {
		var book model.Book
		title := tx.ISBN
		if err := database.DB.Where("isbn = ?", tx.ISBN).First(&book).Error; err == nil {
			title = book.Title
		}

		msg := fmt.Sprintf("REQUEST APPROVED: Your requested book \"%s\" is ready. Please claim it at the library desk.", title)
		sendStudentNotification(tx.SchoolID, msg)
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Book borrow request approved",
		Data:    nil,
	})
}

func RejectBorrowRequestHandler(c *fiber.Ctx) error {
	var input services.RejectBorrowRequestInput

	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode404,
			IsSuccess: false,
			Error:     err,
		})
	}

	if input.TransactionID == 0 || input.RejectReason == "" || input.Staff == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode401,
			IsSuccess: false,
			Error:     nil,
		})
	}

	if err := services.RejectBorrowRequestService(input); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
			Message:   err.Error(),
			IsSuccess: false,
			Error:     err,
		})
	}

	var tx model.Transaction
	if err := database.DB.First(&tx, input.TransactionID).Error; err == nil {
		var book model.Book
		title := tx.ISBN
		if err := database.DB.Where("isbn = ?", tx.ISBN).First(&book).Error; err == nil {
			title = book.Title
		}

		msg := fmt.Sprintf("REQUEST REJECTED: Your request for the book \"%s\" could not be processed. Reason: %s.", title, input.RejectReason)
		sendStudentNotification(tx.SchoolID, msg)
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Book borrow request rejected.",
		Data:    nil,
	})
}

func AddBookBorrowHandler(c *fiber.Ctx) error {
	var input services.AddBookBorrowInput

	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode404,
			IsSuccess: false,
			Error:     err,
		})
	}

	if input.SchoolID == "" || input.ISBN == "" || input.Staff == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode401,
			IsSuccess: false,
			Error:     nil,
		})
	}

	if err := services.AddBookBorrowService(input); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
			Message:   err.Error(),
			IsSuccess: false,
			Error:     err,
		})
	}

	var book model.Book
	title := input.ISBN
	if err := database.DB.Where("isbn = ?", input.ISBN).First(&book).Error; err == nil {
		title = book.Title
	}

	msg := fmt.Sprintf("BOOK BORROWED: You have successfully borrowed the book \"%s\". Please return it on or before the due date.", title)
	sendStudentNotification(input.SchoolID, msg)

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Book borrow added.",
		Data:    nil,
	})
}

func ProcessBookBorrowHandler(c *fiber.Ctx) error {
	var input services.ProcessBookBorrowInput

	if err := c.BodyParser(&input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode404,
			IsSuccess: false,
			Error:     err,
		})
	}

	if input.TransactionID == 0 || input.ISBN == "" || input.Staff == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode401,
			IsSuccess: false,
			Error:     nil,
		})
	}

	if err := services.ProcessBookBorrowService(input); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(errormodel.ErrorModel{
			Message:   err.Error(),
			IsSuccess: false,
			Error:     err,
		})
	}

	var tx model.Transaction
	if err := database.DB.First(&tx, input.TransactionID).Error; err == nil {
		var book model.Book
		title := tx.ISBN
		if err := database.DB.Where("isbn = ?", tx.ISBN).First(&book).Error; err == nil {
			title = book.Title
		}

		msg := fmt.Sprintf("BOOK BORROWED: You have successfully borrowed the book \"%s\". Please return it on or before the due date.", title)
		sendStudentNotification(tx.SchoolID, msg)
	}

	return c.Status(fiber.StatusOK).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Book borrow succeed.",
		Data:    nil,
	})
}

func GetAllTransactions(c *fiber.Ctx) error {
	var transactions []model.Transaction

	if err := database.DB.Order("created_at asc").Find(&transactions).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"isSuccess": false, "message": "Failed to fetch transactions"})
	}

	return c.JSON(fiber.Map{"isSuccess": true, "data": transactions})
}

func GetStaffHistory(c *fiber.Ctx) error {
	var history []model.TransactionHistory

	if err := database.DB.Order("date DESC").Where("event != ?", "Request").Find(&history).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"retCode":   "500",
			"isSuccess": false,
			"message":   "Failed to fetch transactions",
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"retCode":   "200",
		"isSuccess": true,
		"data":      history,
	})
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
		Staff          string `json:"staff"`
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

	now := time.Now()

	user.ViolationCount += input.ViolationCount
	if input.ViolationCount > 0 {
		user.OffenseCount += 1

		base := now
		if user.EndLockDate.After(now) {
			base = user.EndLockDate
		}
		user.EndLockDate = base.AddDate(0, 0, input.ViolationCount)

		if user.OffenseCount >= 3 {
			user.Status = "Locked"
		}
	}

	transaction.Violation = input.Violation
	if input.OverduePoint < 1 {
		transaction.Status = "Returned"
	} else {
		transaction.Status = "Returned Late"
	}
	transaction.DateReturned = now

	tx := database.DB.Begin()

	if err := tx.Save(&user).Error; err != nil {
		tx.Rollback()
		return c.Status(500).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Failed to update user.",
		})
	}

	if err := tx.Save(&transaction).Error; err != nil {
		tx.Rollback()
		return c.Status(500).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Failed to update transaction.",
		})
	}

	var book model.Book
	if err := tx.Where("isbn = ?", transaction.ISBN).First(&book).Error; err != nil {
		tx.Rollback()
		return c.Status(500).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Book not found.",
		})
	}

	beforeAvailable := book.Available

	book.Available += 1

	if beforeAvailable == 0 {
		go services.NotifyWishlistUsers(book.ISBN, book.Title)
	}

	if err := tx.Save(&book).Error; err != nil {
		tx.Rollback()
		return c.Status(500).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Failed to update book availability.",
		})
	}

	history := model.TransactionHistory{
		TransactionID: transaction.ID,
		SchoolID:      transaction.SchoolID,
		ISBN:          transaction.ISBN,
		Event:         "Return",
		Staff:         input.Staff,
		Date:          time.Now(),
	}

	if err := tx.Create(&history).Error; err != nil {
		tx.Rollback()
		return c.Status(500).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Failed to save transaction history.",
		})
	}

	if err := tx.Commit().Error; err != nil {
		return c.Status(500).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Transaction commit failed.",
		})
	}

	if err := tx.Commit().Error; err != nil {
		return c.Status(500).JSON(fiber.Map{
			"isSuccess": false,
			"message":   "Transaction commit failed.",
		})
	}

	title := transaction.ISBN
	if err := database.DB.Where("isbn = ?", transaction.ISBN).First(&book).Error; err == nil {
		title = book.Title
	}

	msg := fmt.Sprintf("BOOK RETURNED: Your borrowed \"%s\" has been successfully returned.", title)
	if input.ViolationCount > 0 {
		msg = fmt.Sprintf("BOOK RETURNED: Your borrowed \"%s\" has been successfully returned. Due to your violation (%s), you have %d-day borrow ban.", title, input.Violation, input.ViolationCount)
	}
	sendStudentNotification(transaction.SchoolID, msg)

	if user.OffenseCount >= 3 && user.Status == "Locked" {
		fullName := user.FirstName + " " + user.LastName
		go utils.SendAccountLockedEmail(user.Email, fullName)
	}

	return c.Status(200).JSON(response.ResponseModel{
		RetCode: "200",
		Message: "Book marked as returned.",
	})
}

func GetStudentTransaction(c *fiber.Ctx) error {
	schoolID := c.Params("school_id")

	if schoolID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode404,
			IsSuccess: false,
			Error:     nil,
		})
	}

	history, err := services.GetStudentTransactionService(schoolID)
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

func GetStudentAllTransaction(c *fiber.Ctx) error {
	schoolID := c.Params("school_id")

	if schoolID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode404,
			IsSuccess: false,
			Error:     nil,
		})
	}

	history, err := services.GetStudentAllTransactionService(schoolID)
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

func GetStudentHistory(c *fiber.Ctx) error {
	schoolID := c.Params("school_id")

	if schoolID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(errormodel.ErrorModel{
			Message:   status.RetCode404,
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

func GetWholeHistory(c *fiber.Ctx) error {
	history, err := services.GetWholeHistoryService()
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

// ==========================================
//  HELPER FUNCTION PARA SA NOTIFICATIONS
// ==========================================

func sendStudentNotification(schoolID string, message string) {
	notif := model.Notification{
		SchoolID: schoolID,
		Message:  message,
		IsRead:   false,
	}
	database.DB.Create(&notif)

	payload := services.NotificationPayload{
		ID:   int64(notif.ID),
		Msg:  message,
		Time: time.Now().Format("Jan 02, 3:04 PM"),
		Read: false,
	}
	services.NotifHub.SendNotification(schoolID, payload)
}
