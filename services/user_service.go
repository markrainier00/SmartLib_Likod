package services

import (
	"SmartLib_Likod/repositories"
)

type StudentHistoryOutput struct {
	BookTitle    string `json:"book_title"`
	Author       string `json:"author"`
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
			BookTitle:    record.BookTitle,
			Author:       record.Author,
			Status:       record.Status,
			BorrowDate:   record.BorrowDate,
			ReturnDate:   record.ReturnDate,
			DateReturned: record.DateReturned,
		}
	}

	return history, nil
}
