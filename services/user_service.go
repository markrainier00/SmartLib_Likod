package services

import (
	"SmartLib_Likod/database"
	"SmartLib_Likod/model"
	"SmartLib_Likod/repositories"
)

type StudentHistoryOutput struct {
	ISBN         string `json:"isbn"`
	Status       string `json:"status"`
	BorrowDate   string `json:"borrow_date"`
	ReturnDate   string `json:"return_date"`
	DateReturned string `json:"date_returned"`
}

type ApproveInput struct {
	UserID uint `json:"user_id"`
}

type RejectInput struct {
	UserID uint   `json:"user_id"`
	Reason string `json:"reason"`
}

type UpdateUserStatusInput struct {
	SchoolID string `json:"school_id"`
	Status   string `json:"status"`
}

// DAPAT NANDITO ANG MGA FUNCTIONS NA ITO
func ApproveUserService(input ApproveInput) error {
	// ... yung logic na sinend mo kanina ...
	return nil
}

func GetStudentHistoryService(schoolID string) ([]StudentHistoryOutput, error) {
	historyRecords, err := repositories.GetTransactionHistory(schoolID)
	if err != nil {
		return nil, err
	}

	history := make([]StudentHistoryOutput, len(historyRecords))
	for i, record := range historyRecords {
		history[i] = StudentHistoryOutput{
			ISBN:         record.ISBN,
			Status:       record.Status,
			BorrowDate:   record.BorrowDate.Format("2006-01-02"),
			ReturnDate:   record.ReturnDate.Format("2006-01-02"),
			DateReturned: record.DateReturned.Format("2006-01-02"),
		}
	}

	return history, nil
}
func RejectUserService(input RejectInput) error {
	// ... yung logic na sinend mo kanina ...
	return nil
}

func GetAllUsersService() ([]model.User, error) {
	var users []model.User
	result := database.DB.Find(&users)
	return users, result.Error
}

func UpdateUserStatusService(input UpdateUserStatusInput) error {
	// ... logic ...
	return nil
}

func DeleteUserService(schoolID string) error {
	// ... logic ...
	return nil
}

func GetAllRequestsService() ([]model.Transaction, error) {
	var transactions []model.Transaction
	result := database.DB.Find(&transactions)
	return transactions, result.Error
}

func GetRegistrationHistoryService() ([]model.RegistrationRequest, error) {
	return repositories.GetRegistrationHistory()
}
