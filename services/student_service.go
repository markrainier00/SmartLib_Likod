package services

import (
	"SmartLib_Likod/repositories"
)

// StudentHistoryOutput - Structure ng data na ibabalik sa frontend
type StudentHistoryOutput struct {
	ISBN         string `json:"isbn"`
	Status       string `json:"status"`
	BorrowDate   string `json:"borrow_date"`
	ReturnDate   string `json:"return_date"`
	DateReturned string `json:"date_returned"`
}

// GetStudentHistoryService - Kinukuha ang records mula sa repository at nililinis para sa handler
func GetStudentHistoryService(schoolID string) ([]StudentHistoryOutput, error) {
	// Tatawagin nito ang function sa repositories/transaction_repository.go (o kung nasaan man ang logic)
	historyRecords, err := repositories.GetTransactionHistory(schoolID)
	if err != nil {
		return nil, err
	}

	history := make([]StudentHistoryOutput, len(historyRecords))
	for i, record := range historyRecords {
		history[i] = StudentHistoryOutput{
			ISBN:         record.ISBN,
			Status:       record.Status,
			BorrowDate:   record.BorrowDate,
			ReturnDate:   record.ReturnDate,
			DateReturned: record.DateReturned,
		}
	}

	return history, nil
}
