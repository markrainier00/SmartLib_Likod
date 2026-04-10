package services

import (
	"SmartLib_Likod/repositories"
)

type StudentHistoryOutput struct {
	ISBN         string `json:"isbn"`
	Status       string `json:"status"`
	BorrowDate   string `json:"borrow_date"`
	ReturnDate   string `json:"return_date"`
	DateReturned string `json:"date_returned"`
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
