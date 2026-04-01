package repositories

import (
	"SmartLib_Likod/database"
	"SmartLib_Likod/model"
)

// Adds new book
func AddBook(book *model.Book) error {
	return database.DB.Create(book).Error
}
