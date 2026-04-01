package services

import (
	"errors"

	"SmartLib_Likod/model"
	"SmartLib_Likod/repositories"
)

type BookInput struct {
	Title           string `gorm:"type:varchar(255);not null" json:"title"`
	Author          string `gorm:"type:varchar(255);not null" json:"author"`
	ISBN            string `gorm:"type:varchar(20);unique" json:"isbn"`
	Publisher       string `gorm:"type:varchar(150)" json:"publisher"`
	PublicationDate string `gorm:"type:varchar(50)" json:"publication_date"`
	Edition         string `gorm:"type:varchar(50)" json:"edition"`
	Category        string `gorm:"type:varchar(500)" json:"category"`
	Pages           string `gorm:"default:1" json:"pages"`
	Copies          string `gorm:"default:1" json:"copies"`
	Description     string `gorm:"type:text" json:"description"`
	ActualImage     string `gorm:"type:text" json:"actual_image"`
}

func BookInputService(input BookInput) (*model.Book, error) {
	book := &model.Book{
		Title:           input.Title,
		Author:          input.Author,
		ISBN:            input.ISBN,
		Publisher:       input.Publisher,
		PublicationDate: input.PublicationDate,
		Edition:         input.Edition,
		Category:        input.Category,
		Pages:           input.Pages,
		Copies:          input.Copies,
		Description:     input.Description,
		ActualImage:     input.ActualImage,
	}

	if err := repositories.AddBook(book); err != nil {
		return nil, errors.New("Failed to create user")
	}

	return book, nil
}
