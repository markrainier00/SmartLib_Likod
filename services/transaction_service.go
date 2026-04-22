package services

import (
	"fmt"
	"time"

	"SmartLib_Likod/database"
	"SmartLib_Likod/model"
	"SmartLib_Likod/repositories"

	"gorm.io/gorm"
)

type RequestInput struct {
	Title      string `json:"title"`
	SchoolID   string `json:"school_id"`
	ISBN       string `json:"isbn"`
	PickupDate string `json:"pickup_date"`
}

type ApproveBorrowRequestInput struct {
	TransactionID uint   `json:"id"`
	SchoolID      string `json:"school_id"`
	ISBN          string `json:"isbn"`
	Staff         string `json:"staff"`
}

type RejectBorrowRequestInput struct {
	TransactionID uint   `json:"id"`
	SchoolID      string `json:"school_id"`
	ISBN          string `json:"isbn"`
	RejectReason  string `json:"reject_reason"`
	Staff         string `json:"staff"`
}

type ProcessBookBorrowInput struct {
	TransactionID uint      `json:"id"`
	SchoolID      string    `json:"school_id"`
	ISBN          string    `json:"isbn"`
	Staff         string    `json:"staff"`
	BorrowDate    time.Time `json:"borrow_date"`
	ReturnDate    time.Time `json:"return_date"`
}

type BorrowInput struct {
	SchoolID   string `json:"school_id"`
	ISBN       string `json:"isbn"`
	BorrowDate string `json:"borrow_date"`
	ReturnDate string `json:"return_date"`
}

type Wishlist struct {
	SchoolID string `json:"school_id"`
	ISBN     string `json:"isbn"`
}

type StudentTransactionOutput struct {
	ID           uint   `json:"id"`
	ISBN         string `json:"isbn"`
	Status       string `json:"status"`
	BorrowDate   string `json:"borrow_date"`
	ReturnDate   string `json:"return_date"`
	DateReturned string `json:"date_returned"`
	RejectReason string `json:"reject_reason"`
	Violation    string `json:"violation"`
	CreatedAt    string `json:"created_at"`
}

type StudentHistoryOutput struct {
	ID    uint      `json:"transaction_id"`
	ISBN  string    `json:"isbn"`
	Event string    `json:"event"`
	Date  time.Time `json:"date"`
}

type WholeHistoryOutput struct {
	ID       uint      `json:"transaction_id"`
	SchoolID string    `json:"school_id"`
	ISBN     string    `json:"isbn"`
	Event    string    `json:"event"`
	Date     time.Time `json:"date"`
}

func RequestBookService(input RequestInput) error {
	pickupDate, err := time.Parse("2006-01-02", input.PickupDate)
	if err != nil {
		return err
	}

	if pickupDate.Before(time.Now().Truncate(24 * time.Hour)) {
		return fmt.Errorf("The selected pickup date is invalid. It must not be earlier than today.")
	}

	request := &model.Transaction{
		SchoolID:   input.SchoolID,
		ISBN:       input.ISBN,
		Status:     "Pending",
		PickupDate: pickupDate,
	}

	tx := database.DB.Begin()

	if err := tx.Create(request).Error; err != nil {
		tx.Rollback()
		return err
	}

	history := &model.TransactionHistory{
		TransactionID: request.ID,
		SchoolID:      request.SchoolID,
		ISBN:          request.ISBN,
		Event:         "Request",
		Date:          time.Now(),
	}

	if err := tx.Create(history).Error; err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit().Error
}

func ApproveBorrowRequestService(input ApproveBorrowRequestInput) error {
	var transaction model.Transaction
	var book model.Book
	var user model.User

	return database.DB.Transaction(func(tx *gorm.DB) error {

		if err := tx.Where("school_id = ?", input.SchoolID).First(&user).Error; err != nil {
			return fmt.Errorf("User not found")
		}

		if err := tx.First(&transaction, input.TransactionID).Error; err != nil {
			return fmt.Errorf("Request not found")
		}

		if transaction.Status != "Pending" {
			return fmt.Errorf("Request already processed")
		}

		if err := tx.Where("isbn = ?", input.ISBN).First(&book).Error; err != nil {
			return fmt.Errorf("Book not found")
		}

		if book.Available <= 0 {
			return fmt.Errorf("No copies available")
		}

		transaction.Status = "Approved"
		transaction.ApproveDate = time.Now()

		if err := tx.Save(&transaction).Error; err != nil {
			return err
		}

		book.Available -= 1
		if err := tx.Save(&book).Error; err != nil {
			return err
		}

		book.Reserved += 1
		if err := tx.Save(&book).Error; err != nil {
			return err
		}

		history := model.TransactionHistory{
			TransactionID: transaction.ID,
			SchoolID:      transaction.SchoolID,
			ISBN:          transaction.ISBN,
			Event:         "Approve",
			Staff:         input.Staff,
			Date:          time.Now(),
		}

		if err := tx.Create(&history).Error; err != nil {
			return err
		}

		return nil
	})
}

func RejectBorrowRequestService(input RejectBorrowRequestInput) error {
	var transaction model.Transaction
	var book model.Book
	var user model.User

	return database.DB.Transaction(func(tx *gorm.DB) error {

		if err := tx.Where("school_id = ?", input.SchoolID).First(&user).Error; err != nil {
			return fmt.Errorf("User not found")
		}

		if err := tx.First(&transaction, input.TransactionID).Error; err != nil {
			return fmt.Errorf("Request not found")
		}

		if transaction.Status != "Pending" {
			return fmt.Errorf("Request already processed")
		}

		if err := tx.Where("isbn = ?", input.ISBN).First(&book).Error; err != nil {
			return fmt.Errorf("Book not found")
		}

		transaction.RejectReason = input.RejectReason
		transaction.Status = "Rejected"
		transaction.RejectDate = time.Now()

		if err := tx.Save(&transaction).Error; err != nil {
			return err
		}

		if err := tx.Save(&book).Error; err != nil {
			return err
		}

		history := model.TransactionHistory{
			TransactionID: transaction.ID,
			SchoolID:      transaction.SchoolID,
			ISBN:          transaction.ISBN,
			Event:         "Reject",
			Staff:         input.Staff,
			Date:          time.Now(),
		}

		if err := tx.Create(&history).Error; err != nil {
			return err
		}

		return nil
	})
}

func ProcessBookBorrowService(input ProcessBookBorrowInput) error {
	var transaction model.Transaction
	var book model.Book
	var user model.User

	if input.ReturnDate.Before(time.Now().Truncate(24 * time.Hour)) {
		return fmt.Errorf("The selected return date is invalid. It must not be earlier than today.")
	}

	today := time.Now().Truncate(24 * time.Hour)
	maxDate := today.AddDate(0, 0, 7)

	if input.ReturnDate.After(maxDate) {
		return fmt.Errorf("The selected return date is invalid. It must not be more than 7 days from today.")
	}

	return database.DB.Transaction(func(tx *gorm.DB) error {

		if err := tx.Where("school_id = ?", input.SchoolID).First(&user).Error; err != nil {
			return fmt.Errorf("User not found")
		}

		if err := tx.First(&transaction, input.TransactionID).Error; err != nil {
			return fmt.Errorf("Request not found")
		}

		if transaction.Status != "Approved" {
			return fmt.Errorf("Request already processed")
		}

		if err := tx.Where("isbn = ?", input.ISBN).First(&book).Error; err != nil {
			return fmt.Errorf("Book not found")
		}

		if book.Reserved <= 0 {
			return fmt.Errorf("No copies reserved")
		}

		transaction.Status = "Borrowed"
		transaction.BorrowDate = input.BorrowDate
		transaction.ReturnDate = input.ReturnDate

		if err := tx.Save(&transaction).Error; err != nil {
			return err
		}

		book.Reserved -= 1
		if err := tx.Save(&book).Error; err != nil {
			return err
		}

		history := model.TransactionHistory{
			TransactionID: transaction.ID,
			SchoolID:      transaction.SchoolID,
			ISBN:          transaction.ISBN,
			Event:         "Borrow",
			Staff:         input.Staff,
			Date:          time.Now(),
		}

		if err := tx.Create(&history).Error; err != nil {
			return err
		}

		return nil
	})
}

func AddWishlistService(input Wishlist) error {
	w := &model.Wishlist{
		SchoolID: input.SchoolID,
		ISBN:     input.ISBN,
	}
	return repositories.AddWishlist(w)
}

func RemoveWishlistService(input Wishlist) error {
	return repositories.RemoveWishlist(input.SchoolID, input.ISBN)
}

func GetUserWishlistService(schoolID string) ([]Wishlist, error) {
	var wishlist []model.Wishlist

	if err := database.DB.
		Where("school_id = ?", schoolID).
		Find(&wishlist).Error; err != nil {
		return nil, err
	}

	var result []Wishlist
	for _, w := range wishlist {
		result = append(result, Wishlist{
			SchoolID: w.SchoolID,
			ISBN:     w.ISBN,
		})
	}

	return result, nil
}

// func BorrowBookService(input BorrowInput) error {
// 	count, err := repositories.HasActiveBorrow(input.SchoolID)
// 	if err != nil {
// 		return err
// 	}

// 	if count >= 3 {
// 		return errors.New("you already have an active borrowed book")
// 	}

// 	tx := &model.Transaction{
// 		SchoolID:   input.SchoolID,
// 		ISBN:       input.ISBN,
// 		Status:     "Pending",
// 		BorrowDate: input.BorrowDate,
// 	}

// 	return repositories.CreateTransaction(tx)
// }

func GetStudentTransactionService(schoolID string) ([]StudentTransactionOutput, error) {
	transactionRecords, err := repositories.GetStudentTransaction(schoolID)
	if err != nil {
		return nil, err
	}

	transaction := make([]StudentTransactionOutput, len(transactionRecords))
	for i, record := range transactionRecords {
		transaction[i] = StudentTransactionOutput{
			ID:           record.ID,
			ISBN:         record.ISBN,
			Status:       record.Status,
			BorrowDate:   record.BorrowDate.Format("2006-01-02"),
			ReturnDate:   record.ReturnDate.Format("2006-01-02"),
			DateReturned: record.DateReturned.Format("2006-01-02"),
			RejectReason: record.RejectReason,
			Violation:    record.Violation,
		}
	}

	return transaction, nil
}

func GetStudentAllTransactionService(schoolID string) ([]StudentTransactionOutput, error) {
	transactionRecords, err := repositories.GetStudentAllTransaction(schoolID)
	if err != nil {
		return nil, err
	}

	transaction := make([]StudentTransactionOutput, len(transactionRecords))
	for i, record := range transactionRecords {
		transaction[i] = StudentTransactionOutput{
			ID:           record.ID,
			ISBN:         record.ISBN,
			Status:       record.Status,
			BorrowDate:   record.BorrowDate.Format("2006-01-02"),
			ReturnDate:   record.ReturnDate.Format("2006-01-02"),
			DateReturned: record.DateReturned.Format("2006-01-02"),
			RejectReason: record.RejectReason,
			Violation:    record.Violation,
			CreatedAt:    record.CreatedAt.Format("2006-01-02"),
		}
	}

	return transaction, nil
}

func GetStudentHistoryService(schoolID string) ([]StudentHistoryOutput, error) {
	historyRecords, err := repositories.GetStudentHistory(schoolID)
	if err != nil {
		return nil, err
	}

	history := make([]StudentHistoryOutput, len(historyRecords))
	for i, record := range historyRecords {
		history[i] = StudentHistoryOutput{
			ID:    record.TransactionID,
			ISBN:  record.ISBN,
			Event: record.Event,
			Date:  record.Date,
		}
	}

	return history, nil
}

func GetWholeHistoryService() ([]WholeHistoryOutput, error) {
	historyRecords, err := repositories.GetWholeHistory()
	if err != nil {
		return nil, err
	}

	history := make([]WholeHistoryOutput, len(historyRecords))
	for i, record := range historyRecords {
		history[i] = WholeHistoryOutput{
			ID:       record.TransactionID,
			SchoolID: record.SchoolID,
			ISBN:     record.ISBN,
			Event:    record.Event,
			Date:     record.Date,
		}
	}

	return history, nil
}
