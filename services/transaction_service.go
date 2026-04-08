package services

import (
	"time"

	"SmartLib_Likod/model"
	"SmartLib_Likod/repositories"
)

type RequestInput struct {
	SchoolID   string `json:"school_id"`
	ISBN       string `json:"isbn"`
	PickupDate string `json:"pickup_date"`
}

type BorrowInput struct {
	SchoolID   string `json:"school_id"`
	ISBN       string `json:"isbn"`
	BorrowDate string `json:"borrow_date"`
	ReturnDate string `json:"return_date"`
}

type WishlistInput struct {
	SchoolID string `json:"school_id"`
	ISBN     string `json:"isbn"`
}

func RequestBookService(input RequestInput) error {
	pickupDate, err := time.Parse("2006-01-02", input.PickupDate)
	if err != nil {
		return err
	}

	request := &model.Transaction{
		SchoolID:   input.SchoolID,
		ISBN:       input.ISBN,
		Status:     "Pending",
		PickupDate: pickupDate,
	}

	return repositories.CreateRequest(request)
}

func AddWishlistService(input WishlistInput) error {
	w := &model.Wishlist{
		SchoolID: input.SchoolID,
		ISBN:     input.ISBN,
	}
	return repositories.AddWishlist(w)
}

func RemoveWishlistService(input WishlistInput) error {
	return repositories.RemoveWishlist(input.SchoolID, input.ISBN)
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

func ReleaseBookService(schoolID string) error {
	return repositories.ReleaseBookStatus(schoolID)
}
