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

type WishlistInput struct {
	SchoolID string `json:"school_id"`
	ISBN     string `json:"isbn"`
}

// 🔔 Helper Function: Save to DB & Send SSE
func saveAndSendNotification(schoolID string, message string) {
	newNotif := &model.Notification{
		SchoolID: schoolID,
		Message:  message,
		IsRead:   false,
	}

	// Save to DB
	repositories.CreateNotification(newNotif)

	// Payload for SSE
	payload := NotificationPayload{
		ID:   int64(newNotif.ID),
		Msg:  message,
		Time: time.Now().Format("Jan 02, 3:04 PM"),
		Read: false,
	}

	// Send to active client (direkta nang tinatawag ang NotifHub dito)
	NotifHub.SendNotification(schoolID, payload)
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

	err = repositories.CreateRequest(request)
	if err != nil {
		return err
	}

	// Trigger Notification
	msg := "Your book request for ISBN " + input.ISBN + " has been submitted."
	saveAndSendNotification(input.SchoolID, msg)

	return nil
}

func AddWishlistService(input WishlistInput) error {
	w := &model.Wishlist{
		SchoolID: input.SchoolID,
		ISBN:     input.ISBN,
	}

	err := repositories.AddWishlist(w)
	if err != nil {
		return err
	}

	msg := "Book added to your wishlist!"
	saveAndSendNotification(input.SchoolID, msg)

	return nil
}

func RemoveWishlistService(input WishlistInput) error {
	return repositories.RemoveWishlist(input.SchoolID, input.ISBN)
}

func ReleaseBookService(schoolID string, isbn string) error {
	err := repositories.ReleaseBookStatus(schoolID)
	if err != nil {
		return err
	}

	msg := "Your book (ISBN: " + isbn + ") is now released. Happy reading!"
	saveAndSendNotification(schoolID, msg)

	return nil
}

func ApproveRequestService(schoolID string, isbn string) error {
	msg := "Your request for ISBN " + isbn + " has been APPROVED. Please visit the library."
	saveAndSendNotification(schoolID, msg)
	return nil
}
