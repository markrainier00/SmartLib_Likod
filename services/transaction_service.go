package services

import (
	"SmartLib_Likod/model"
	"SmartLib_Likod/repositories"
	"errors"
)

type BorrowInput struct {
	SchoolID   string `json:"school_id"`
	BookTitle  string `json:"book_title"`
	PickupDate string `json:"pickup_date"`
	ReturnDate string `json:"return_date"`
}

func BorrowBookService(input BorrowInput) error {
	// ✅ FIX: HasPendingTransaction → HasActiveBorrow
	// Hindi na naka-block ang student na mag-request kahit may existing pending
	if repositories.HasActiveBorrow(input.SchoolID) {
		return errors.New("you already have an active borrowed book")
	}

	tx := &model.Transaction{
		SchoolID:  input.SchoolID,
		BookTitle: input.BookTitle,
		Status:    "Pending",
		// PickupDate: input.PickupDate,
		ReturnDate: input.ReturnDate,
	}

	return repositories.CreateTransaction(tx)
}

func ReleaseBookService(schoolID string) error {
	return repositories.ReleaseBookStatus(schoolID)
}
